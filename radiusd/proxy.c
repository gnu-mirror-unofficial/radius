/* This file is part of GNU Radius.
   Copyright (C) 2000,2002,2003 Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/*FIXME!FIXME!FIXME! server timeout is not used */

#define RADIUS_MODULE_PROXY_C

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

/* ************************************************************************* */
/* Functions local to this module */

static UINT4
get_socket_addr(int fd)
{
	struct sockaddr_in sin;
	int len = sizeof(sin);
	UINT4 ip = 0;

	if (getsockname(fd, (struct sockaddr*)&sin, &len) == 0)
		ip = sin.sin_addr.s_addr;

	if (ip == INADDR_ANY)
		ip = ref_ip;
	return ip;
}


/*
 *      Decode a password and encode it again.
 */
static void
passwd_recode(VALUE_PAIR *pass_pair, char *new_secret, char *new_vector,
	      RADIUS_REQ *req)
{
        char    password[AUTH_STRING_LEN+1];
        req_decrypt_password(password, req, pass_pair);
        string_free(pass_pair->avp_strvalue);
        encrypt_password(pass_pair, password, new_vector, new_secret);
        /* Don't let the cleantext hang around */
        memset(password, 0, AUTH_STRING_LEN);
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 * There appear to be two cases: i) when the remote server retains the
 * Proxy-State A/V pair, which seems to correspond to RFC 2865,
 * and ii) when the remote server drops the Proxy-State pair.
 */

int
proxy_cmp(RADIUS_REQ *qr, RADIUS_REQ *r)
{
	VALUE_PAIR *p, *proxy_state_pair = NULL;
        PROXY_STATE *state;
	
	if (!qr->server) {
		debug(100,("no proxy server"));
		return 1;
	}
        /* Find the last PROXY_STATE attribute. */
        for (p = r->request; p; p = p->next) {
                if (p->attribute == DA_PROXY_STATE) 
                        proxy_state_pair = p;
        }
	
        state = proxy_state_pair ?
                   (PROXY_STATE *)proxy_state_pair->avp_strvalue : NULL;
	
        if (state) {
		debug(1,
		      ("state: ipaddr %08x, id %u, proxy_id %u, rem_ipaddr %08x",
		       state->ipaddr,
		       state->id,
		       state->proxy_id,
		       state->rem_ipaddr));
		
                if (state->proxy_id   == r->id
		    && state->rem_ipaddr == r->ipaddr) {
			debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x, proxy_id %d %d, server_addr %#8x %#8x", 
				   qr->id, state->id,
				   qr->ipaddr, state->ipaddr,
				   qr->server_id, state->proxy_id,
				   qr->server->addr, state->rem_ipaddr));
        
			if (state->ipaddr == qr->ipaddr
			    && state->id  == qr->id
			    && state->proxy_id == qr->server_id
			    && state->rem_ipaddr == qr->server->addr) {
				debug(1,("EQUAL!!!"));
				return 0;
			}
		} 
	} else if (qr->server_id) {
		debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x",
			   qr->server_id,
			   r->id,
			   qr->server->addr,
			   r->ipaddr));
                        
		if (r->ipaddr == qr->server->addr
		    && r->id == qr->server_id)
			return 0;
	}
	return 1;
}

/* ************************************************************************* */
/* Reply functions. Possibly these should go to libclient? */

int
proxy_send_request(int fd, RADIUS_REQ *radreq)
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
		radlog_req(L_NOTICE, radreq,
		           _("couldn't send request to realm %s"),
		           radreq->realm->realm);
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
        p->avp_strlength = sizeof(PROXY_STATE);
        p->avp_strvalue = string_alloc(p->avp_strlength);
        
        proxy_state = (PROXY_STATE *)p->avp_strvalue;
	       
        proxy_state->ipaddr = radreq->ipaddr; /*FIXME: get_socket_addr(fd);*/
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

                debug(1, ("Proxying id %d to %lx",
                          radreq->id, (u_long)server->addr));

		sendto(fd, pdu, size, 0, (struct sockaddr *)&sin, sizeof(sin));
	}
	return size;
}

/* ************************************************************************* */
/* Interface functions */

/* Relay the request to a remote server
   Returns:  1 success (we reply, caller returns without replying)
             0 fail (caller falls through to normal processing)
             -1 fail (we don't reply, caller returns without replying) */

int
proxy_send(REQUEST *req)
{
	RADIUS_REQ *radreq = req->data;
        int rc;
        char *saved_username;
        char *username;
        VALUE_PAIR *namepair;
        VALUE_PAIR *vp;
        char *realmname;
        REALM *realm;
        char *what;
        RADIUS_UPDATE *upd;

        /* Look up name. */
        namepair = avl_find(radreq->request, DA_USER_NAME);
        if (namepair == NULL)
                return 0;

        saved_username = estrdup(namepair->avp_strvalue);
        username = namepair->avp_strvalue;

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
                        namepair->avp_strlength = strlen(namepair->avp_strvalue);
                }
                efree(saved_username);
                return 0;
        }

	radreq->realm = realm;
        if (realmname) {
                if (realm->striprealm)
                        *realmname = 0;
        }
        
        string_replace(&namepair->avp_strvalue, username);
        namepair->avp_strlength = strlen(namepair->avp_strvalue);

        radreq->server = realm->queue->first_server;
	radreq->attempt_no = 0;
        radreq->server_id = rad_clt_message_id(radreq->server);
	radreq->remote_user = string_create(username);

	req->update_size = sizeof(*upd) + strlen(realm->realm);
	upd = emalloc(req->update_size);
	upd->proxy_id = radreq->server_id;
	upd->server_no = 0;
	strcpy(upd->realmname, realm->realm);
	req->update = upd;
	
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
                vp->avp_strlength = AUTH_VECTOR_LEN;
                vp->avp_strvalue = string_alloc(AUTH_VECTOR_LEN);
                memcpy(vp->avp_strvalue, radreq->vector, AUTH_VECTOR_LEN);
                avl_add_pair(&radreq->request, vp);
        }

        efree(saved_username);
	
	proxy_send_request(req->fd, radreq);
	
        return 1;
}

/* FIXME: Unused */
void
proxy_retry(int type, void *data, void *orig_data,
	    int fd, char *status_str)
{
	RADIUS_REQ *radreq = data ? data : orig_data;
	RADIUS_REQ *orig_req = orig_data;
	VALUE_PAIR *namepair;
	char *saved_username;
	
	if (!(orig_req && radreq)) {
		radius_req_drop(type, radreq, orig_req, fd, status_str);
		return;
	}
	
	/* If both request and original request are given, try to retransmit
	   the request */

        namepair = avl_find(radreq->request, DA_USER_NAME);
        if (namepair == NULL)
                return;

        saved_username = namepair->avp_strvalue;
        namepair->avp_strvalue = orig_req->remote_user;
        namepair->avp_strlength = strlen(namepair->avp_strvalue);

	proxy_send_request(fd, orig_req);

	/* restore username */
	namepair->avp_strvalue = saved_username;
        namepair->avp_strlength = strlen(namepair->avp_strvalue);
}


int
select_allowed(void *null ARG_UNUSED, VALUE_PAIR *pair)
{
        return pair->prop & AP_PROPAGATE;
}

/* Called when a response from a remote radius server has been received.
   The function finds the original request and replaces all fields in
   radreq, except `request' with the original data.
   Return:   0 proxy found
            -1 error don't reply */
int
proxy_receive(RADIUS_REQ *radreq, RADIUS_REQ *oldreq, int fd)
{
        VALUE_PAIR *vp, *proxy_state_pair, *prev, *x;
        VALUE_PAIR *allowed_pairs;
        PROXY_STATE *state;
        
        /* Remove the last proxy pair from the list. */
	/* FIXME: Should be done by proxy_cmp ? */
        proxy_state_pair = x = prev = NULL;

        for (vp = radreq->request; vp; vp = vp->next) {
                if (vp->attribute == DA_PROXY_STATE) {
                        prev = x;
                        proxy_state_pair = vp;
                }
                x = vp;
        }

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

