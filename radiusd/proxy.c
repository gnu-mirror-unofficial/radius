/* This file is part of GNU Radius.
   Copyright (C) 2000,2002,2003,2004,2006,2007,
   2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

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

/* Decode a password and encode it again. */
static void
passwd_recode(grad_avp_t *pass_pair, char *new_secret, char *new_authenticator,
	      radiusd_request_t *req)
{
        char password[GRAD_STRING_LENGTH+1];
        req_decrypt_password(password, req->request, pass_pair);
        grad_free(pass_pair->avp_strvalue);
        grad_encrypt_password(pass_pair, password, new_authenticator, new_secret);
        /* Don't let the cleantext hang around */
        memset(password, 0, GRAD_STRING_LENGTH);
}

/* Decode a password and encode it again. */
static void
tunnel_passwd_recode(grad_avp_t *pass_pair, char *new_secret, char *new_authenticator,
		     radiusd_request_t *req)
{
        char password[GRAD_STRING_LENGTH+1];
	u_char tag;
	
	grad_decrypt_tunnel_password(password, 
				     &tag, pass_pair,
				     req->request->authenticator,
				     req->request->secret);
        grad_free(pass_pair->avp_strvalue);
	grad_encrypt_tunnel_password(pass_pair,
				     tag, password, 
				     new_authenticator, new_secret);
	memset(password, 0, GRAD_STRING_LENGTH);
}

grad_avp_t *
proxy_request_recode(radiusd_request_t *radreq, grad_avp_t *plist,
		     u_char *secret, u_char *authenticator)
{
	grad_avp_t *p;

	/* Recode password pair(s) */
	for (p = plist; p; p = p->next) {
		if (p->prop & GRAD_AP_ENCRYPT_RFC2138)
			passwd_recode(p, secret, authenticator, radreq);
		else if (p->prop & GRAD_AP_ENCRYPT_RFC2868)
			tunnel_passwd_recode(p, secret, authenticator, radreq);
	}
	return plist;
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 */

int
proxy_cmp(radiusd_request_t *qr, radiusd_request_t *r)
{
	grad_avp_t *p, *proxy_state_pair = NULL;
	grad_server_t *server;
	
	if (!qr->realm) {
		GRAD_DEBUG(100,"no proxy realm");
		return 1;
	}
	server = grad_list_item(qr->realm->queue->servers, qr->server_no);
	if (!server) {
		GRAD_DEBUG(100,"no proxy server");
		return 1;
	}
	
        /* Find the last PROXY_STATE attribute. */
        for (p = r->request->avlist; p; p = p->next) {
                if (p->attribute == DA_PROXY_STATE) 
                        proxy_state_pair = p;
        }

	if (proxy_state_pair
	    && proxy_state_pair->avp_strlength == sizeof(PROXY_STATE)) {
		PROXY_STATE *state;

		state = (PROXY_STATE *)proxy_state_pair->avp_strvalue;
	
		GRAD_DEBUG4(1,
		      "state: ipaddr %08x, id %u, proxy_id %u, remote_ip %08x",
		       state->client_ip,
		       state->id,
		       state->proxy_id,
		       state->remote_ip);
		
                if (state->ref_ip == ref_ip
		    && state->proxy_id == r->request->id
		    && state->remote_ip == r->request->ipaddr) {
			GRAD_DEBUG8(10, 
                                    "(old=data) id %d %d, ipaddr %#8x %#8x, "
                                    "proxy_id %d %d, server_addr %#8x %#8x", 
				    qr->request->id, state->id,
				    qr->request->ipaddr, state->client_ip,
				    qr->server_id, state->proxy_id,
 				    server->addr, state->remote_ip);
        
			if (state->client_ip == qr->request->ipaddr
			    && state->id  == qr->request->id
			    && state->proxy_id == qr->server_id
			    && state->remote_ip == server->addr) {
				GRAD_DEBUG(1,"EQUAL!!!");
				return 0;
			}
		} 
	}
	
	return 1;
}

/* ************************************************************************* */
/* Reply functions. Possibly these should go to libclient? */

/* Send the request */
static int
proxy_send_pdu(int fd, grad_server_t *server, radiusd_request_t *radreq,
	       void *pdu, size_t size)
{
	struct sockaddr_in sin;
	
	memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(server->addr);
	
	sin.sin_port = htons((radreq->request->code == RT_ACCESS_REQUEST) ?
			     server->port[GRAD_PORT_AUTH] 
			     : server->port[GRAD_PORT_ACCT]);

	GRAD_DEBUG2(1, "Proxying id %d to %lx",
		    radreq->request->id, (u_long)server->addr);

	return sendto(fd, pdu, size, 0, (struct sockaddr *)&sin, sizeof(sin));
}

int
proxy_send_request(int fd, radiusd_request_t *radreq)
{
	grad_avp_t *plist, *p;
	void *pdu;
	size_t size;
	grad_server_t *server;
	int rc;
	PROXY_STATE *proxy_state;
	
	if (radreq->attempt_no >= radreq->realm->queue->retries) {
		radreq->server_no++;
		radreq->attempt_no = 0;
	}
	server = grad_list_item(radreq->realm->queue->servers,
				radreq->server_no);

	if (!server) {
		grad_log_req(GRAD_LOG_NOTICE, radreq->request,
		             _("couldn't send request to realm %s"),
		             radreq->realm->realm);
		return 0;
	}
	if (radreq->attempt_no == 0)
		radreq->server_id = grad_client_message_id(server);
	radreq->attempt_no++;

	grad_client_random_authenticator(radreq->remote_auth);
	plist = proxy_request_recode(radreq,
				     grad_avl_dup(radreq->request->avlist),
				     server->secret,
				     radreq->remote_auth);

	/* Add a proxy-pair to the end of the request. */
	p = grad_avp_alloc();
	p->name = "Proxy-State";
	p->attribute = DA_PROXY_STATE;
	p->type = GRAD_TYPE_STRING;
	p->avp_strlength = sizeof(PROXY_STATE);
	p->avp_strvalue = grad_emalloc(p->avp_strlength);
	
	proxy_state = (PROXY_STATE *)p->avp_strvalue;
	
	proxy_state->ref_ip = ref_ip;
	proxy_state->client_ip = radreq->request->ipaddr;
	proxy_state->id = radreq->request->id;
	proxy_state->proxy_id = radreq->server_id;
	proxy_state->remote_ip = server->addr;
	
	grad_avl_add_pair(&plist, p);
	
	/* Create the pdu */
	size = grad_create_pdu(&pdu,
			       radreq->request->code,
			       radreq->server_id,
			       radreq->remote_auth,
			       server->secret,
			       plist,
			       NULL);
	grad_avl_free(plist);

	if (!radiusd_master()) {
		RADIUS_UPDATE *upd;
		size_t size;
		
                /* Prepare update data. */
		size = sizeof(*upd) + strlen(radreq->realm->realm) + 1;
		upd = grad_emalloc(size);
		upd->id = radreq->request->id;
		upd->proxy_id = radreq->server_id;
		upd->server_no = radreq->server_no;
		strcpy(upd->realmname, radreq->realm->realm);

		GRAD_DEBUG4(100,
		      "Update id=%d, proxy_id=%d, realm=%s, server_no=%d",
		       upd->id,upd->proxy_id,upd->realmname,
		       upd->server_no);

		rpp_update(upd, size);
		grad_free(upd);
	}
	
	rc = proxy_send_pdu(fd, server, radreq, pdu, size);
	grad_free(pdu);
	return rc;
}

/* ************************************************************************* */
/* Interface functions */

static grad_realm_t *
proxy_lookup_realm(radiusd_request_t *req, char *name)
{
	grad_realm_t *realm = grad_realm_lookup_name(name);
	static char *var[] = { "auth", "acct" };
	int t;
	
	if (realm) {
		int rc;
		switch (req->request->code) {
		case RT_ACCESS_REQUEST:
			t = R_AUTH;
			break;
		
		case RT_ACCOUNTING_REQUEST:
			t = R_ACCT;
			break;
			
		default:
			/* Should not happen.. */
			grad_insist_fail("unexpected request code");
		}

		rc = grad_envar_lookup_int(realm->args, var[t], -1);
		if (rc == -1) {
			/* Neither {var} nor no{var} is specified. Check
			   the orthogonal variable. If it is not set, proxying
			   is enabled for both authentication and
			   accounting. */
			rc = !grad_envar_lookup_int(realm->args, var[!t], 0);
		}
		if (!rc)
			realm = NULL;
		
	}
	return realm;
}

/* Relay the request to a remote server
   Returns:  1 success (we reply, caller returns without replying)
             0 fail (caller falls through to normal processing)
             -1 fail (we don't reply, caller returns without replying) */

int
proxy_send(REQUEST *req)
{
	radiusd_request_t *radreq = req->data;
        char *username;
        grad_avp_t *namepair;
        grad_avp_t *vp;
        char *realmname;
        grad_realm_t *realm;

        /* Look up name. */
        namepair = grad_avl_find(radreq->request->avlist, DA_USER_NAME);
        if (grad_avp_null_string_p(namepair))
                return 0;

        username = namepair->avp_strvalue;

        /* Find the realm from the _end_ so that we can cascade realms:
           user@realm1@realm2. A special realms NOREALM matches usual
	   user name (without explicit realm). A realm named DEFAULT is
	   returned by grad_realm_lookup_name() if no other realm name
	   matches.

	   In addition, a keyword LOCAL in server list fields indicates
	   that the realm should be handled locally */

        if ((realmname = strrchr(username, '@')) == NULL) {
                if ((realm = grad_realm_lookup_name("NOREALM")) == NULL) {
                        return 0;
                }
        } else if ((realm = proxy_lookup_realm(radreq, realmname + 1))
		     == NULL) {
                /* If the realm is not found, we treat it as usual. */
                return 0;
        }

	if (realmname && grad_realm_strip_p(realm)) {
		*realmname = 0;
		namepair->avp_strlength = strlen(namepair->avp_strvalue);
	}

	if (realm->queue == NULL) /* This is a LOCAL realm */
                return 0;

	radreq->realm = realm;
        radreq->server_no = 0;
	radreq->attempt_no = 0;
	/* Actual user name may be altered, but the remote user name
	   should remain the same */
	radreq->remote_user = grad_estrdup(username); 

	/* Add a Realm-Name pair */
	grad_avl_add_pair(&radreq->request->avlist,
			  grad_avp_create_string(DA_REALM_NAME, realm->realm));
	
        /* If there is a DA_CHAP_PASSWORD attribute, there is
	   also a DA_CHAP_CHALLENGE. If you change the code of
	   radius_auth_req_decode(), you will have
	   to manually take care of this. */

	proxy_send_request(req->fd, radreq);

        return 1;
}

/* FIXME! server timeout is not used */
void
proxy_retry(radiusd_request_t *req, int fd)
{
	grad_avp_t *namepair;
	char *saved_username;
	
        namepair = grad_avl_find(req->request->avlist, DA_USER_NAME);
        if (namepair == NULL)
                return;

        saved_username = namepair->avp_strvalue;
        namepair->avp_strvalue = req->remote_user;
        namepair->avp_strlength = strlen(namepair->avp_strvalue);

	proxy_send_request(fd, req);

	/* restore username */
	namepair->avp_strvalue = saved_username;
        namepair->avp_strlength = strlen(namepair->avp_strvalue);
}

static int
select_propagated(void *null ARG_UNUSED, grad_avp_t *pair)
{
        return pair->prop & GRAD_AP_PROPAGATE;
}

/* Called when a response from a remote radius server has been received.
   The function finds the original request and replaces all fields in
   radreq, except `request->avlist', with the original data.
   Return:   0 proxy found
            -1 error don't reply */
int
proxy_receive(radiusd_request_t *radreq, radiusd_request_t *oldreq, int fd)
{
        grad_avp_t *vp, *proxy_state_pair, *prev, *x;
        grad_avp_t *allowed_pairs;
	
        /* Remove the last proxy pair from the list. */
        proxy_state_pair = x = prev = NULL;

        for (vp = radreq->request->avlist; vp; vp = vp->next) {
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
                        radreq->request->avlist = proxy_state_pair->next;
                grad_avp_free(proxy_state_pair);
        }

        /* Only allow some attributes to be propagated from
           the remote server back to the NAS, for security. */
        allowed_pairs = NULL;
        grad_avl_move_pairs(&allowed_pairs, &radreq->request->avlist,
			    select_propagated, NULL);
        grad_avl_free(radreq->request->avlist);

        /* Rebuild the radiusd_request_t struct, so that the normal functions
           can process it. Take care not to modify oldreq! */

	memcpy(radreq->request->authenticator,
	       oldreq->remote_auth, sizeof radreq->request->authenticator);
 	radreq->server_reply = proxy_request_recode(radreq, allowed_pairs,
						    oldreq->request->secret,
						    oldreq->request->authenticator);
        radreq->validated    = 1;
        radreq->server_code  = radreq->request->code;
        radreq->request->code = oldreq->request->code;

        radreq->request->ipaddr       = oldreq->request->ipaddr;
        radreq->request->udp_port     = oldreq->request->udp_port;
        radreq->request->id           = oldreq->request->id;

	memcpy(radreq->request->authenticator,
	       oldreq->request->authenticator,
	       sizeof radreq->request->authenticator);
        radreq->request->secret       = oldreq->request->secret;
        radreq->request->avlist       = grad_avl_dup(oldreq->request->avlist);

        /* Proxy support fields */
        radreq->realm         = oldreq->realm;
        radreq->server_no     = oldreq->server_no;
        radreq->server_id     = oldreq->server_id;
        
        return 0;
}

