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

/*
 *      Decode a password and encode it again.
 */
static void
passwd_recode(VALUE_PAIR *pass_pair, char *new_secret, char *new_vector,
	      RADIUS_REQ *req)
{
        char password[AUTH_STRING_LEN+1];
        req_decrypt_password(password, req, pass_pair);
        efree(pass_pair->avp_strvalue);
        encrypt_password(pass_pair, password, new_vector, new_secret);
        /* Don't let the cleantext hang around */
        memset(password, 0, AUTH_STRING_LEN);
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 */

int
proxy_cmp(RADIUS_REQ *qr, RADIUS_REQ *r)
{
	VALUE_PAIR *p, *proxy_state_pair = NULL;
	RADIUS_SERVER *server;
	
	if (!qr->realm) {
		debug(100,("no proxy realm"));
		return 1;
	}
	server = list_item(qr->realm->queue->servers, qr->server_no);
	if (!server) {
		debug(100,("no proxy server"));
		return 1;
	}
	
        /* Find the last PROXY_STATE attribute. */
        for (p = r->request; p; p = p->next) {
                if (p->attribute == DA_PROXY_STATE) 
                        proxy_state_pair = p;
        }

	if (proxy_state_pair
	    && proxy_state_pair->avp_strlength == sizeof(PROXY_STATE)) {
		PROXY_STATE *state;

		state = (PROXY_STATE *)proxy_state_pair->avp_strvalue;
	
		debug(1,
		      ("state: ipaddr %08x, id %u, proxy_id %u, remote_ip %08x",
		       state->client_ip,
		       state->id,
		       state->proxy_id,
		       state->remote_ip));
		
                if (state->ref_ip == ref_ip
		    && state->proxy_id == r->id
		    && state->remote_ip == r->ipaddr) {
			debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x, proxy_id %d %d, server_addr %#8x %#8x", 
				   qr->id, state->id,
				   qr->ipaddr, state->client_ip,
				   qr->server_id, state->proxy_id,
				   server->addr, state->remote_ip));
        
			if (state->client_ip == qr->ipaddr
			    && state->id  == qr->id
			    && state->proxy_id == qr->server_id
			    && state->remote_ip == server->addr) {
				debug(1,("EQUAL!!!"));
				return 0;
			}
		} 
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
		radreq->server_no++;
		radreq->attempt_no = 0;
	}
	server = list_item(radreq->realm->queue->servers, radreq->server_no);

	if (!server) {
		radlog_req(L_NOTICE, radreq,
		           _("couldn't send request to realm %s"),
		           radreq->realm->realm);
		return 0;
	}
	if (radreq->attempt_no == 0)
		radreq->server_id = rad_clt_message_id(server);
	radreq->attempt_no++;

	rad_clt_random_vector(vector);

	/* Copy the list */
	plist = avl_dup(radreq->request);

	/* Recode password pair(s) */
	for (p = plist; p; p = p->next) {
		if (p->attribute == DA_USER_PASSWORD
		    || p->attribute == DA_CHAP_PASSWORD)
			passwd_recode(p, server->secret, vector, radreq);
	}
	
	/* Add a proxy-pair to the end of the request. */
        p = avp_alloc();
        p->name = "Proxy-State";
        p->attribute = DA_PROXY_STATE;
        p->type = TYPE_STRING;
        p->avp_strlength = sizeof(PROXY_STATE);
        p->avp_strvalue = emalloc(p->avp_strlength);
        
        proxy_state = (PROXY_STATE *)p->avp_strvalue;

	proxy_state->ref_ip = ref_ip;
        proxy_state->client_ip = radreq->ipaddr;
        proxy_state->id = radreq->id;
        proxy_state->proxy_id = radreq->server_id;
        proxy_state->remote_ip = server->addr;

	avl_add_pair(&plist, p);

	/* Create the pdu */
	size = rad_create_pdu(&pdu, radreq->code,
			      radreq->server_id,
			      vector,
			      server->secret,
			      plist,
			      NULL);
	avl_free(plist);

	if (!radiusd_master()) {
		RADIUS_UPDATE *upd;
		size_t size;
		
                /* Prepare update data. */
		size = sizeof(*upd) + strlen(radreq->realm->realm) + 1;
		upd = emalloc(size);
		upd->id = radreq->id;
		upd->proxy_id = radreq->server_id;
		upd->server_no = radreq->server_no;
		strcpy(upd->realmname, radreq->realm->realm);

		debug(100,
		      ("Update id=%d, proxy_id=%d, realm=%s, server_no=%d",
		       upd->id,upd->proxy_id,upd->realmname,
		       upd->server_no));

		rpp_update(upd, size);
		efree(upd);
	}
	
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

        /* Look up name. */
        namepair = avl_find(radreq->request, DA_USER_NAME);
        if (avp_null_string(namepair))
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
        
	if (username[0]==0)
		abort();
        string_replace(&namepair->avp_strvalue, username);
	if (namepair->avp_strvalue[0]==0)
		abort();
        namepair->avp_strlength = strlen(namepair->avp_strvalue);

        radreq->server_no = 0;
	radreq->attempt_no = 0;
	radreq->remote_user = estrdup(username);

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
                vp->avp_strvalue = emalloc(AUTH_VECTOR_LEN);
                memcpy(vp->avp_strvalue, radreq->vector, AUTH_VECTOR_LEN);
                avl_add_pair(&radreq->request, vp);
        }

        efree(saved_username);
	
	proxy_send_request(req->fd, radreq);

        return 1;
}

/* FIXME! server timeout is not used */
void
proxy_retry(RADIUS_REQ *radreq, RADIUS_REQ *orig_req, int fd)
{
	VALUE_PAIR *namepair;
	char *saved_username;
	
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


static int
select_propagated(void *null ARG_UNUSED, VALUE_PAIR *pair)
{
        return pair->prop & AP_PROPAGATE;
}

/* Called when a response from a remote radius server has been received.
   The function finds the original request and replaces all fields in
   radreq, except `request', with the original data.
   Return:   0 proxy found
            -1 error don't reply */
int
proxy_receive(RADIUS_REQ *radreq, RADIUS_REQ *oldreq, int fd)
{
        VALUE_PAIR *vp, *proxy_state_pair, *prev, *x;
        VALUE_PAIR *allowed_pairs;
        PROXY_STATE *state;
        
        /* Remove the last proxy pair from the list. */
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
        avl_move_pairs(&allowed_pairs, &radreq->request,
		       select_propagated, NULL);
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
        radreq->server_no     = oldreq->server_no;
        radreq->server_id     = oldreq->server_id;
        
        return 0;
}

