/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/*FIXME!FIXME!FIXME! server timeout is not used */

#define RADIUS_MODULE_PROXY_C
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

#include <radiusd.h>

static PROXY_ID *proxy_id;

static void random_vector(char *vector);
static VALUE_PAIR *proxy_addinfo(RADIUS_REQ *radreq, int proxy_id, int fd, UINT4 remip);
void proxy_addrequest(RADIUS_REQ *radreq);
static void passwd_recode(VALUE_PAIR *pair,
                          char *new_secret, char *new_vector, RADIUS_REQ *req);
static int proxy_send_request(int fd, RADIUS_REQ *radreq);
static UINT4 get_socket_addr(int fd);

/* ************************************************************************* */
/* Proxy-Id functions */
/* We try to keep a separate proxy_id per remote server so that if we happen
 * to have a lot of proxy requests the proxy id wouldn't wrap around too
 * fast.
 * From the other hand, we can't keep the proxy id in the client struct since
 * it would be reset to zero after each reload of configuration files.
 * This approach has two drawbacks:
 *   1. Linear search. If we have too many clients, its performance will
 *      degradate.
 *   2. Suppose we delete a client and then do a reload. In that case this
 *      client's proxy_id record will hang around just wasting memory. Hence,
 *      the need of proxy_cleanup function.
 */

/* next_proxy_id(): return next proxy id for the given client's IP address.
 * If we don't have one, create it and initialize to zero.
 */
u_char
next_proxy_id(ipaddr)
        UINT4 ipaddr;
{
        PROXY_ID *p;

        for (p = proxy_id; p; p = p->next)
                if (p->ipaddr == ipaddr)
                        break;
        if (!p) {
                p = alloc_entry(sizeof *p);
                p->ipaddr = ipaddr;
                p->id = 0;
                p->next = proxy_id;
                proxy_id = p;
        }
        return p->id++;
}

/* Delete any proxy_id's that do not correspond to existing clients
 */
void
proxy_cleanup()
{
        PROXY_ID *p, *prev, *next;

        prev = NULL;
        for (p = proxy_id; p; ) {
                next = p->next;
                if (!client_lookup_ip(p->ipaddr)) {
                        if (prev) 
                                prev->next = next;
                        else
                                proxy_id = next;
                        free_entry(p);
                }
                p = next;
        }
}

/* ************************************************************************* */
/* Request-queue functions */

/* rad_proxy(): Called right after the request has been added to the request
 * list. The function just creates a dynamic copy of raw request data and
 * attaches it to the request.
 */
/*ARGSUSED*/
int
rad_proxy(radreq, activefd)
        RADIUS_REQ *radreq;
        int activefd;
{
        void *ptr;
        
        /*
         *      Copy the static data into malloc()ed memory.
         */
        ptr = emalloc(radreq->data_len);
        debug(1,("allocated ptr %p", ptr));
        memcpy(ptr, radreq->data, radreq->data_len);
        radreq->data = ptr;
        radreq->data_alloced = 1;

        return 0;
}


/* ************************************************************************* */
/* Reply functions. Possibly these should go to libclient? */

int
proxy_send_request(fd, radreq)
	int fd;
	RADIUS_REQ *radreq;
{
	VALUE_PAIR *plist, *p;
        PROXY_STATE *proxy_state;
	char vector[AUTH_VECTOR_LEN];
	void *pdu;
	size_t size;
	struct sockaddr_in sin;
	RADIUS_SERVER *server;
	
	if (radreq->attempt_no > radreq->realm->queue->retries) {
		radreq->server = radreq->server->next;
		radreq->attempt_no = 0;
	}

	if (!radreq->server) {
		radlog(L_NOTICE,
		       _("couldn't send %s request to realm %s, id %d"),
		       auth_code_str(radreq->code),
		       radreq->realm->realm, radreq->server_id);
		return 0;
	}
	radreq->attempt_no++;

	server = radreq->server;
	rad_clt_random_vector(vector);

	/* Copy the list */
	plist = avl_dup(radreq->request);

	/* Recode password pair(s) */
	for (p = plist; p; p = p->next) {
		if (p->attribute == DA_USER_PASSWORD
		    || p->attribute == DA_CHAP_PASSWORD)
			passwd_recode(p, server->secret,
				      vector, radreq);
	}
	
	/* Add a proxy-pair to the end of the request. */
        p = avp_alloc();
        p->name = "Proxy-State";
        p->attribute = DA_PROXY_STATE;
        p->type = TYPE_STRING;
        p->strlength = sizeof(PROXY_STATE);
        p->strvalue = alloc_string(p->strlength);
        
        proxy_state = (PROXY_STATE *)p->strvalue;
	       
        proxy_state->ipaddr = get_socket_addr(fd);
        proxy_state->id = radreq->id;
        proxy_state->proxy_id = radreq->server_id;
        proxy_state->rem_ipaddr = server->addr;

	avl_add_pair(&plist, p);

	/* Create the pdu */
	size = rad_create_pdu(&pdu, radreq->code,
			      radreq->server_id,
			      vector,
			      server->secret,
			      plist,
			      NULL);
	avl_free(plist);

	if (size > 0) {
		/* Send the request */
		memset(&sin, 0, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(server->addr);
	
		sin.sin_port = htons(
			(radreq->code == RT_AUTHENTICATION_REQUEST) ?
			server->port[PORT_AUTH] : server->port[PORT_ACCT]);
		sendto(fd, pdu, size, 0, (struct sockaddr *)&sin, sizeof(sin));
	}
	return size;
}

/* ************************************************************************* */
/* Functions local to this module */

static UINT4
get_socket_addr(fd)
	int fd;
{
	struct sockaddr_in sin;
	int len = sizeof(sin);
	UINT4 ip = 0;

	/* FIXME: if fd was bound to INADDR_ANY, there is not much sense
	   in doing this. The possible solution will be to use if_nameindex
	   (or SIOCGIFCONF) to get the IP of the first available interface */
	   
	if (getsockname(fd, (struct sockaddr*)&sin, &len) == 0)
		ip = sin.sin_addr.s_addr;
	return ip;
}


/*
 *      Decode a password and encode it again.
 */
static void
passwd_recode(pass_pair, new_secret, new_vector, req)
        VALUE_PAIR *pass_pair;
        char *new_secret;
        char *new_vector;
        RADIUS_REQ *req;
{
        char    password[AUTH_STRING_LEN+1];
        req_decrypt_password(password, req, pass_pair);
        free_string(pass_pair->strvalue);
        encrypt_password(pass_pair, password, new_vector, new_secret);
        /* Don't let the cleantext hang around */
        memset(password, 0, AUTH_STRING_LEN);
}

/* ************************************************************************* */
/* Interface functions */

/* Relay the request to a remote server
   Returns:  1 success (we reply, caller returns without replying)
             0 fail (caller falls through to normal processing)
             -1 fail (we don't reply, caller returns without replying) */

int
proxy_send(radreq, activefd)
        RADIUS_REQ *radreq;
        int activefd;
{
        int rc;
        char *saved_username;
        char *username;
        VALUE_PAIR *namepair;
        VALUE_PAIR *vp, *pp;
        char *realmname;
        REALM *realm;
        CLIENT *client;
        short rport;
        char *what;
        char *secret_key;
        char buf[MAX_LONGNAME];
        
        /* Look up name. */
        namepair = avl_find(radreq->request, DA_USER_NAME);
        if (namepair == NULL)
                return 0;

        saved_username = estrdup(namepair->strvalue);
        username = namepair->strvalue;

        /* Find the realm from the _end_ so that we can cascade realms:
           user@realm1@realm2. Two special realms are handled separately:
           
               LOCAL    -- process request locally.
               NOREALM  -- handle an empty realm name.

           A realm with special name DEFAULT is returned by realm_lookup_name()
           if no other realm name matches. */

        if ((realmname = strrchr(username, '@')) == NULL) {
                if ((realm = realm_lookup_name("NOREALM")) == NULL) {
                        efree(saved_username);
                        return 0;
                }
        } else if ((realm = realm_lookup_name(realmname + 1)) == NULL) {
                /* If the realm is not found, we treat it as usual. */
                efree(saved_username);
                return 0;
        } else if (realm->queue == NULL) { /* This is a LOCAL realm */
                if (realm->striprealm) {
                        *realmname = 0;
                        namepair->strlength = strlen(namepair->strvalue);
                }
                efree(saved_username);
                return 0;
        }

	radreq->realm = realm;
        if (realmname) {
                if (realm->striprealm)
                        *realmname = 0;
        }
        
        replace_string(&namepair->strvalue, username);
        namepair->strlength = strlen(namepair->strvalue);

        radreq->server = realm->queue->first_server;
	radreq->attempt_no = 0;
        radreq->server_id = next_proxy_id(radreq->server->addr);
	radreq->remote_user = make_string(username);
	
        /* Is this a valid & signed request ? */
        switch (radreq->code) {
        case RT_AUTHENTICATION_REQUEST:
                what = _("authentication");
                rc = 0;
                break;
        case RT_ACCOUNTING_REQUEST:
                what = _("accounting");
                rc = calc_acctdigest(radreq) < 0;
                break;
        default:
                what = _("unknown");
                rc = 1;
        }

        if (rc) {
                radlog(L_NOTICE,
                       _("%s request from client %s for user %s - Security Breach"),
                       what,
                       client_lookup_name(radreq->ipaddr, buf, sizeof buf),
                       namepair->strvalue);
                efree(saved_username);
                return -1;
        }

        /* If there is no DA_CHAP_CHALLENGE attribute but there
           is a DA_CHAP_PASSWORD we need to add it since we can't
	   use the request authenticator anymore - we changed it. */
        if (avl_find(radreq->request, DA_CHAP_PASSWORD) &&
            avl_find(radreq->request, DA_CHAP_CHALLENGE) == NULL) {
                vp = avp_alloc();
                
                memset(vp, 0, sizeof(VALUE_PAIR));

                vp->name = "CHAP-Challenge";
                vp->attribute = DA_CHAP_CHALLENGE;
                vp->type = TYPE_STRING;
                vp->strlength = AUTH_VECTOR_LEN;
                vp->strvalue = alloc_string(AUTH_VECTOR_LEN);
                memcpy(vp->strvalue, radreq->vector, AUTH_VECTOR_LEN);
                avl_add_pair(&radreq->request, vp);
        }

        /* Now build a new request and send it to the remote radiusd. */
        proxy_send_request(activefd, radreq);
        
#if 1   
        /* And restore username. */
        replace_string(&namepair->strvalue, saved_username);
        namepair->strlength = strlen(namepair->strvalue);
#endif
        efree(saved_username);

        return 1;
}

void
proxy_retry(type, radreq, orig_req, fd, status_str)
        int type;
        RADIUS_REQ *radreq;
	RADIUS_REQ *orig_req;
	int fd;
        char *status_str;
{
	VALUE_PAIR *namepair;
	char *saved_username;
	
	if (!(orig_req && radreq)) {
		rad_req_drop(type, radreq, orig_req, fd, status_str);
		return;
	}
	
	/* If both request and original request are given, try to retransmit
	   the request */

        namepair = avl_find(radreq->request, DA_USER_NAME);
        if (namepair == NULL)
                return;

        saved_username = namepair->strvalue;
        namepair->strvalue = orig_req->remote_user;
        namepair->strlength = strlen(namepair->strvalue);

	proxy_send_request(fd, orig_req);

	/* restore username */
	namepair->strvalue = saved_username;
        namepair->strlength = strlen(namepair->strvalue);
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 * There appear to be two cases: i) when the remote server retains the
 * Proxy-State A/V pair, which seems to correspond to RFC 2865,
 * and ii) when the remote server drops the Proxy-State pair.
 */

struct proxy_data {
	UINT4 ipaddr;
        PROXY_STATE *state;
        RADIUS_REQ  *radreq;
};

/* proxy_compare_request(): Find matching request based on the information
   preserved in the Proxy-State pair. */
int
proxy_compare_request(data, oldreq)
        struct proxy_data *data;
        RADIUS_REQ *oldreq;
{
        debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x", 
                oldreq->id,data->state->id,data->ipaddr,data->state->ipaddr));
        
        if (data->state->ipaddr     == data->ipaddr
	    && data->state->id      == oldreq->id) 
                return 0;

        return 1;
}

/* proxy_compare_request_no_state(): Find matching outstanding request if the
   server did not retain the Proxy-State pair.
   miquels@cistron.nl says:
        Some servers drop the proxy pair. So
        compare in another way if needed.
        FIXME: hmmm, perhaps we don't even need Proxy-State
        after all! */
int
proxy_compare_request_no_state(data, oldreq)
        struct proxy_data *data;
        RADIUS_REQ *oldreq;
{
        debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x",
		   oldreq->server_id,
		   data->radreq->id,
		   oldreq->server->addr,
		   data->radreq->ipaddr));
                        
        if (data->radreq->ipaddr == oldreq->server->addr &&
            data->radreq->id     == oldreq->server_id)
                return 0;

        return 1;
}


int
select_allowed(unused, pair)
        void *unused;
        VALUE_PAIR *pair;
{
        return pair->prop & AP_PROPAGATE;
}

/* Called when a response from a remote radius server has been received.
   The function finds the original request and replaces all fields in
   radreq, except `request' with the original data.
   Return:   0 proxy found
            -1 error don't reply */
int
proxy_receive(radreq, activefd)
        RADIUS_REQ        *radreq;
        int             activefd;
{
        VALUE_PAIR      *vp, *proxy_state_pair, *prev, *x;
        VALUE_PAIR      *allowed_pairs;
        RADIUS_REQ      *oldreq;
        PROXY_STATE     *state;
        struct proxy_data data;
        char buf[MAX_LONGNAME];
        
        /* FIXME: calculate md5 checksum! */

        /* Find the last PROXY_STATE attribute. */

        oldreq  = NULL;
        proxy_state_pair = x = prev = NULL;

        for (vp = radreq->request; vp; vp = vp->next) {
                if (vp->attribute == DA_PROXY_STATE) {
                        prev = x;
                        proxy_state_pair = vp;
                }
                x = vp;
        }

        state = proxy_state_pair ?
                   (PROXY_STATE *)proxy_state_pair->strvalue : NULL;

        if (state)
          debug(1, ("state: ipaddr %08x, id %u, proxy_id %u, rem_ipaddr %08x",
                 state->ipaddr,
                 state->id,
                 state->proxy_id,
                 state->rem_ipaddr));

        /* Find matching request in the list of outstanding requests. */
	data.ipaddr = get_socket_addr(activefd);
	data.state = state;
        data.radreq = radreq;
	
        debug(1, ("Compare: myip %08x, radreq->id %d, radreq->ipaddr %08x",
		  data.ipaddr, radreq->id, radreq->ipaddr));
        
        if (state) {
                if (state->proxy_id   == radreq->id &&
                    state->rem_ipaddr == radreq->ipaddr) {
                        oldreq = request_scan_list(R_PROXY,
                                                   proxy_compare_request,
                                                   &data);
                } else {
                        oldreq = NULL;
                }
        } else {
                oldreq = request_scan_list(R_PROXY,
                                           proxy_compare_request_no_state,
                                           &data);
        }
        
        if (oldreq == NULL) {
                radlog(L_PROXY|L_ERR,
                       _("Unrecognized proxy reply from server %s - ID %d"),
                       client_lookup_name(radreq->ipaddr, buf, sizeof buf),
                       radreq->id);
                return -1;
        }

        /* Remove proxy pair from the list. */
        if (proxy_state_pair) {
                if (prev)
                        prev->next = proxy_state_pair->next;
                else
                        radreq->request = proxy_state_pair->next;
                avp_free(proxy_state_pair);
        }

        /* Only allow some attributes to be propagated from
           the remote server back to the NAS, for security. */
        allowed_pairs = NULL;
        avl_move_pairs(&allowed_pairs, &radreq->request, select_allowed, NULL);
        avl_free(radreq->request);

        /* Rebuild the RADIUS_REQ struct, so that the normal functions
           can process it. Take care not to modify oldreq! */
        
        radreq->server_reply = allowed_pairs;
        radreq->validated    = 1;
        radreq->server_code  = radreq->code;
        radreq->code         = oldreq->code;

        radreq->ipaddr       = oldreq->ipaddr;
        radreq->udp_port     = oldreq->udp_port;
        radreq->id           = oldreq->id;
        memcpy(radreq->vector, oldreq->vector, sizeof radreq->vector);
        radreq->secret       = oldreq->secret;
        radreq->request      = avl_dup(oldreq->request);

        /* Proxy support fields */
        radreq->realm         = oldreq->realm;
        radreq->server        = oldreq->server;
        radreq->server_id     = oldreq->server_id;
        
        return 0;
}

