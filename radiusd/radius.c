/* This file is part of GNU Radius.
   Copyright (C) 2000, 2002, 2003, Sergey Poznyakoff
  
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

#define RADIUS_MODULE_RADIUS_C
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radiusd.h>

/* Build and send a reply to the incoming request.
   Input: code        -- Reply code.
          radreq      -- The request.
          reply_pairs -- List of A/V pairs to be encoded in the reply
          msg         -- User message
          fd          -- Socket descriptor.
    NOTE: If radreq contains cached reply information, this information
          is used instead of the supplied arguments. */

void
radius_send_reply(int code, RADIUS_REQ *radreq,
		  VALUE_PAIR *reply_pairs, char *msg, int fd)
{
        if (radreq->reply_code == 0) {
                VALUE_PAIR *reply;
                
                /* Save the data */
                radreq->reply_code = code;
                radreq->reply_msg = estrdup(msg);

                reply = avl_dup(reply_pairs);
                avl_move_attr(&reply, &radreq->request, DA_PROXY_STATE);
                
                switch (code) {
                case RT_PASSWORD_REJECT:
                case RT_AUTHENTICATION_REJECT:
                        radreq->reply_pairs = NULL;
                        avl_move_attr(&radreq->reply_pairs, &reply, 
                                      DA_REPLY_MESSAGE);
                        avl_move_attr(&radreq->reply_pairs, &reply, 
                                      DA_PROXY_STATE);
                        avl_free(reply);
                        break;

                default:
                        radreq->reply_pairs = reply;
                }
        } 

	rad_srv_send_reply(fd, radreq);
}
	
#ifdef USE_LIVINGSTON_MENUS
/* Reply to the request with a CHALLENGE. Also attach any user message
   provided and a state value.
   Input: radreq      -- The request.
          msg         -- User message.
          state       -- Value of the State attribute.
          fd          -- Socket descriptor. */
void
radius_send_challenge(RADIUS_REQ *radreq, char *msg, char *state, int fd)
{
	radreq->reply_pairs = NULL;
	avl_move_attr(&radreq->reply_pairs, &radreq->request, DA_PROXY_STATE);
	if (rad_srv_send_challenge(fd, radreq, msg, state))
		stat_inc(auth, radreq->ipaddr, num_challenges);
}
#endif

/* Validates the requesting client NAS. */
static int
validate_client(RADIUS_REQ *radreq)
{
        CLIENT  *cl;
        
        if ((cl = client_lookup_ip(radreq->ipaddr)) == NULL) {
                radlog_req(L_ERR, radreq, _("request from unknown client"));
                return -1;
        }

        /* Save the secret key */
        radreq->secret = cl->secret;

        return 0;
}

/* Validates the requesting NAS */
int
radius_verify_digest(REQUEST *req)
{
	RADIUS_REQ *radreq = req->data;
	size_t len = req->rawsize;
        int  secretlen;
        char zero[AUTH_VECTOR_LEN];
        u_char  *recvbuf;
        u_char digest[AUTH_VECTOR_LEN];

        secretlen = strlen(radreq->secret);

        recvbuf = emalloc(len + secretlen);
        memcpy(recvbuf, req->rawdata, len + secretlen);
        
        /* Older clients have the authentication vector set to
           all zeros. Return `1' in that case. */
        memset(zero, 0, sizeof(zero));
        if (memcmp(radreq->vector, zero, AUTH_VECTOR_LEN) == 0)
                return REQ_AUTH_ZERO;

        /* Zero out the auth_vector in the received packet.
           Then append the shared secret to the received packet,
           and calculate the MD5 sum. This must be the same
           as the original MD5 sum (radreq->vector). */
        memset(recvbuf + 4, 0, AUTH_VECTOR_LEN);
        memcpy(recvbuf + len, radreq->secret, secretlen);
        md5_calc(digest, recvbuf, len + secretlen);
        efree(recvbuf);
        
        return memcmp(digest, radreq->vector, AUTH_VECTOR_LEN) ?
                          REQ_AUTH_BAD : REQ_AUTH_OK;
}


/* *********************** Radius Protocol Support ************************* */

int
radius_req_decode(struct sockaddr_in *sa,
		  void *input, size_t inputsize, void **output)
{
        RADIUS_REQ *radreq;

        radreq = rad_decode_pdu(ntohl(sa->sin_addr.s_addr),
				ntohs(sa->sin_port),
				input,
				inputsize);
	if (!radreq)
		return 1;

	*output = radreq;
	return 0;
}

static VALUE_PAIR *
_extract_pairs(RADIUS_REQ *req, int prop)
{
	static int attrlist[] = { DA_USER_PASSWORD, DA_CHAP_PASSWORD };
	int i;
	VALUE_PAIR *newlist = NULL;
	VALUE_PAIR *pair;
	char password[AUTH_STRING_LEN+1];

	for (pair = req->request; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(attrlist); i++) {
			if (pair->attribute == attrlist[i]
			    && (pair->prop & prop))
				break;
		}

	if (!pair)
		return NULL;

	newlist = avl_dup(req->request);
	for (pair = newlist; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(attrlist); i++) {
			if (pair->attribute == attrlist[i]
			    && (pair->prop & prop)) {
				req_decrypt_password(password, req, pair);
				string_free(pair->avp_strvalue);
				pair->avp_strvalue = string_create(password);
				pair->avp_strlength = strlen(pair->avp_strvalue);
			}
		}
	return newlist;
}

int
radius_req_cmp(void *adata, void *bdata)
{
	RADIUS_REQ *a = adata;
	RADIUS_REQ *b = bdata;
	int prop = 0;
	VALUE_PAIR *alist = NULL, *blist = NULL, *ap, *bp;
	int rc;
	NAS *nas;

	if (proxy_cmp(a, b) == 0)
		return RCMP_PROXY;
	
	if (a->ipaddr != b->ipaddr || a->code != b->code)
		return RCMP_NE;
	
	if (a->id == b->id
	    && memcmp(a->vector, b->vector, sizeof(a->vector)) == 0)
		return RCMP_EQ;

	if (nas = nas_request_to_nas(a))
		prop = envar_lookup_int(nas->args, "compare-atribute-flag", 0);

	if (!prop) {
		switch (a->code) {
		case RT_AUTHENTICATION_REQUEST:
		case RT_AUTHENTICATION_ACK:
		case RT_AUTHENTICATION_REJECT:
		case RT_ACCESS_CHALLENGE:
			prop = auth_comp_flag;
			break;
			
		case RT_ACCOUNTING_REQUEST:
		case RT_ACCOUNTING_RESPONSE:
		case RT_ACCOUNTING_STATUS:
		case RT_ACCOUNTING_MESSAGE:
			prop = acct_comp_flag;
			break;
		}
	}

	if (prop == 0) 
		return RCMP_NE;

	prop |= AP_REQ_CMP;
	alist = _extract_pairs(a, prop);
	blist = _extract_pairs(b, prop);

	ap = alist ? alist : a->request;
	bp = blist ? blist : b->request;
	
	rc = avl_cmp(ap, bp, prop) || avl_cmp(bp, ap, prop);

	avl_free(alist);
	avl_free(blist);
	return rc == 0 ? RCMP_EQ : RCMP_NE;
}

void
radius_req_update(void *req_ptr, void *data_ptr)
{
	RADIUS_REQ *req = req_ptr;
	RADIUS_UPDATE *upd = data_ptr;
	RADIUS_SERVER *server;
	REALM *realm;
	int i;
	
	req->server_id = upd->proxy_id;
	req->realm = realm_lookup_name(upd->realmname);
	req->server_no = upd->server_no;
}

void
radius_req_free(void *req)
{
        debug(1,("enter: %p",req));
        radreq_free((RADIUS_REQ *)req);
        debug(1,("exit"));
}

/*ARGSUSED*/
void
radius_req_drop(int type, void *data, void *orig_data,
		int fd, char *status_str)
{
	RADIUS_REQ *radreq = data ? data : orig_data;
	RADIUS_REQ *origreq = orig_data;
	char buf[MAX_LONGNAME];

        radlog_req(L_NOTICE, radreq,
		   "%s: %s", _("Dropping packet"),  status_str);

        switch (type) {
        case R_AUTH:
                stat_inc(auth, radreq->ipaddr, num_dropped);
                break;
        case R_ACCT:
                stat_inc(acct, radreq->ipaddr, num_dropped);
        }
}

void
radius_req_xmit(REQUEST *request)
{
        RADIUS_REQ *req = request->data;

        if (request->code == 0) {
                radius_send_reply(0, req, NULL, NULL, request->fd);
                radlog_req(L_NOTICE, req, _("Retransmitting %s reply"),
			   request_class[request->type].name);
        } else {
                radius_req_drop(request->type, NULL, req, request->fd,
				_("request failed"));
        }
}

int
radius_req_failure(int type, struct sockaddr_in *addr)
{
	/*FIXME: should do:
	  stat_inc(acct or auth, ntohl(addr->sin_addr.s_addr), num_bad_req);*/
	return 0;
}

int
radius_respond(REQUEST *req)
{
	int rc;
	RADIUS_REQ *radreq = req->data;
	
        if (suspend_flag)
                return 1;
        
        if (validate_client(radreq)) {
                /*FIXME: update stats */
                return -1;
        }

        /* Check if we support this request */
        switch (radreq->code) {
        case RT_AUTHENTICATION_REQUEST:
                stat_inc(auth, radreq->ipaddr, num_access_req);
                if (rad_auth_init(radreq, req->fd) < 0) 
                        return 1;
		/*FALLTHRU*/		
        case RT_ACCOUNTING_REQUEST:
                if (avl_find(radreq->request, DA_USER_NAME) == NULL)
                        break;
                if (proxy_send(req) != 0) {
                        return 0;
                }
		break;
		
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCESS_CHALLENGE:
		if (!req->orig) {
			char buf[MAX_SHORTNAME];
			radlog_req(L_PROXY|L_ERR, radreq,
				   _("Unrecognized proxy reply from server %s, proxy ID %d"),
				   client_lookup_name(radreq->ipaddr,
						      buf, sizeof buf), 
				   radreq->id);
			return 1;
		}
		
		if (proxy_receive(radreq, req->orig->data, req->fd) < 0) {
			return 1;
		}
		break;
	}

        switch (radreq->code) {
        case RT_AUTHENTICATION_REQUEST:
		rad_authenticate(radreq, req->fd);
                break;
		
        case RT_ACCOUNTING_REQUEST:
		/* Check the request authenticator. */
		rc = radius_verify_digest(req);
		if (rc == REQ_AUTH_BAD) 
			stat_inc(acct, radreq->ipaddr, num_bad_sign);
		rad_accounting(radreq, req->fd, rc);
                break;
		
        default:
                stat_inc(acct, radreq->ipaddr, num_unknowntypes);
                radlog_req(L_NOTICE, radreq, _("unknown request code %d"), 
                           radreq->code); 
                return -1;
        }       
        return 0;
}
