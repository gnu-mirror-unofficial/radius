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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radiusd.h>
#include <obstack1.h>

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
radius_auth_req_decode(struct sockaddr_in *sa,
		       void *input, size_t inputsize, void **output)
{
        RADIUS_REQ *radreq;

	log_open(L_AUTH);

        if (suspend_flag) {
		stat_inc(auth, radreq->ipaddr, num_dropped);
                return 1;
	}
        
        radreq = rad_decode_pdu(ntohl(sa->sin_addr.s_addr),
				ntohs(sa->sin_port),
				input,
				inputsize);
	if (!radreq)
		return 1;
        
        if (validate_client(radreq)) {
		stat_inc(auth, radreq->ipaddr, num_dropped);
		radreq_free(radreq);
 		return 1;
        }
	
	/* RFC 2865 p. 2.2:
	   The random challenge can either be included in the
	   CHAP-Challenge attribute or, if it is 16 octets long,
	   it can be placed in the Request Authenticator field of
	   the Access-Request packet. */

	if (avl_find(radreq->request, DA_CHAP_PASSWORD)
	    && !avl_find(radreq->request, DA_CHAP_CHALLENGE)) {
		VALUE_PAIR *p = avp_create_binary(DA_CHAP_CHALLENGE,
					          AUTH_VECTOR_LEN,
					          radreq->vector);
		avl_add_pair(&radreq->request, p);
	}
	
	*output = radreq;
	return 0;
}

int
radius_acct_req_decode(struct sockaddr_in *sa,
		       void *input, size_t inputsize, void **output)
{
        RADIUS_REQ *radreq;

	log_open(L_ACCT);
	
        if (suspend_flag) {
		stat_inc(acct, radreq->ipaddr, num_dropped);
                return 1;
	}
        
        radreq = rad_decode_pdu(ntohl(sa->sin_addr.s_addr),
				ntohs(sa->sin_port),
				input,
				inputsize);
	if (!radreq)
		return 1;
        
        if (validate_client(radreq)) {
		stat_inc(acct, radreq->ipaddr, num_dropped);
		radreq_free(radreq);
 		return 1;
        }

	*output = radreq;
	return 0;
}

static int crypt_attrlist[] = { DA_USER_PASSWORD, DA_CHAP_PASSWORD };

VALUE_PAIR *
radius_decrypt_request_pairs(RADIUS_REQ *req)
{
	VALUE_PAIR *newlist = avl_dup(req->request);
	VALUE_PAIR *pair;
	char password[AUTH_STRING_LEN+1];
	int i;

	for (pair = newlist; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(crypt_attrlist); i++) {
			if (pair->attribute == crypt_attrlist[i]) {
				req_decrypt_password(password, req, pair);
				efree(pair->avp_strvalue);
				pair->avp_strvalue = estrdup(password);
				pair->avp_strlength = strlen(pair->avp_strvalue);
			}
		}
	return newlist;
}

void
radius_destroy_pairs(VALUE_PAIR **p)
{
	VALUE_PAIR *pair;
	int i;
	
	if (!p || !*p)
		return;
	for (pair = *p; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(crypt_attrlist); i++) {
			if (pair->attribute == crypt_attrlist[i]) 
				memset(pair->avp_strvalue, 0,
				       pair->avp_strlength);
		}

	avl_free(*p);
	*p = NULL;
}

static VALUE_PAIR *
_extract_pairs(RADIUS_REQ *req, int prop)
{
	int i;
	VALUE_PAIR *newlist = NULL;
	VALUE_PAIR *pair;
	char password[AUTH_STRING_LEN+1];
	int found = 0;
	
	for (pair = req->request; !found && pair; pair = pair->next) 
		for (i = 0; i < NITEMS(crypt_attrlist); i++) {
			if (pair->attribute == crypt_attrlist[i]
			    && (pair->prop & prop)) {
				found = 1;
				break;
			}
		}

	if (!found)
		return NULL;

	newlist = avl_dup(req->request);
	for (pair = newlist; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(crypt_attrlist); i++) {
			if (pair->attribute == crypt_attrlist[i]
			    && (pair->prop & prop)) {
				req_decrypt_password(password, req, pair);
				efree(pair->avp_strvalue);
				pair->avp_strvalue = estrdup(password);
				pair->avp_strlength = strlen(pair->avp_strvalue);
			}
		}
	return newlist;
}

static int
find_prop(NAS *nas, char *name, int defval)
{
	if (!nas)
		return defval;
	return envar_lookup_int(nas->args, name, defval);
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

	nas = nas_request_to_nas(a);

	switch (a->code) {
	case RT_AUTHENTICATION_REQUEST:
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCESS_CHALLENGE:
		prop = find_prop(nas, "compare-auth-flag", 0);
		if (!prop)
			prop = find_prop(nas, "compare-attribute-flag",
					 auth_comp_flag);
		break;
			
	case RT_ACCOUNTING_REQUEST:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCOUNTING_STATUS:
	case RT_ACCOUNTING_MESSAGE:
		prop = find_prop(nas, "compare-acct-flag", 0);
		if (!prop)
			prop = find_prop(nas, "compare-attribute-flag",
					 acct_comp_flag);
		break;
	}


	if (prop == 0) 
		return RCMP_NE;

	prop = AP_USER_FLAG(prop);
	alist = _extract_pairs(a, prop);
	blist = _extract_pairs(b, prop);

	ap = alist ? alist : a->request;
	bp = blist ? blist : b->request;
	
	rc = avl_cmp(ap, bp, prop) || avl_cmp(bp, ap, prop);

	radius_destroy_pairs(&alist);
	radius_destroy_pairs(&blist);
	
	if (rc == 0) {
		/* We need to replace A/V pairs, authenticator and ID
		   so that the reply is signed correctly.
		   Notice that the raw data will be replaced by
		   request_retransmit() */
		memcpy(a->vector, b->vector, sizeof(a->vector));
		avl_free(a->request);
		a->request = avl_dup(b->request);
		a->id = b->id;
	}
	
	return rc == 0 ? RCMP_EQ : RCMP_NE;
}

void
radius_req_update(void *req_ptr, void *data_ptr)
{
	RADIUS_REQ *req = req_ptr;
	RADIUS_UPDATE *upd = data_ptr;

	if (req->id != upd->id)
		return;
	req->server_id = upd->proxy_id;
	req->realm = realm_lookup_name(upd->realmname);
	req->server_no = upd->server_no;
	debug(1, ("Update request %d: proxy_id=%d, realm=%s, server_no=%d",
		  req->id,upd->proxy_id,upd->realmname,upd->server_no));
}

void
radius_req_free(void *req)
{
        radreq_free((RADIUS_REQ *)req);
}

/*ARGSUSED*/
void
radius_req_drop(int type, void *data, void *orig_data,
		int fd, const char *status_str)
{
	RADIUS_REQ *radreq = data ? data : orig_data;

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
		if (req->reply_code == 0 && req->realm) {
			proxy_retry(req, request->fd);
		} else {
			radius_send_reply(0, req,
					  NULL, NULL, request->fd);
			radlog_req(L_NOTICE, req,
				   _("Retransmitting %s reply"),
				   request_class[request->type].name);
		} 
	} else
		radius_req_drop(request->type, NULL, req, request->fd,
				_("request failed"));

}

int
radius_req_failure(int type, struct sockaddr_in *addr)
{
	switch (type) {
	case R_AUTH:
		stat_inc(auth, ntohl(addr->sin_addr.s_addr), num_bad_req);
		break;

	case R_ACCT:
		stat_inc(acct, ntohl(addr->sin_addr.s_addr), num_bad_req);
	}
	return 0;
}

int
radius_status_server(RADIUS_REQ *radreq, int fd)
{
	radius_send_reply(RT_AUTHENTICATION_ACK, radreq, NULL,
			  "GNU Radius server fully operational",
			  fd);
	return 0;
}

int
radius_respond(REQUEST *req)
{
	int rc;
	RADIUS_REQ *radreq = req->data;

	forward_request(req->type, radreq);

#ifdef USE_SQL
	radiusd_sql_clear_cache();
#endif
        /* Add any specific attributes for this username. */
        hints_setup(radreq);

        /* Check if we support this request */
        switch (radreq->code) {
        case RT_AUTHENTICATION_REQUEST:
                stat_inc(auth, radreq->ipaddr, num_access_req);
                if (rad_auth_init(radreq, req->fd) < 0) 
                        return 1;
		/*FALLTHRU*/
		
        case RT_ACCOUNTING_REQUEST:
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

	case RT_STATUS_SERVER:
		radius_status_server(radreq, req->fd);
		break;
					
        default:
                stat_inc(acct, radreq->ipaddr, num_unknowntypes);
                radlog_req(L_NOTICE, radreq, _("unknown request code %d"), 
                           radreq->code); 
                return -1;
        }       

	radius_trace_path(radreq);
	
        return 0;
}

void
radius_req_register_locus(RADIUS_REQ *req, LOCUS *loc)
{
	switch (req->code) {
	case RT_AUTHENTICATION_REQUEST:
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCESS_CHALLENGE:
		if (!auth_trace_rules)
			return;
		break;
		
	case RT_ACCOUNTING_REQUEST:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCOUNTING_STATUS:
	case RT_ACCOUNTING_MESSAGE:
		if (!acct_trace_rules)
			return;
		break;

	default:
		return;
	}

	if (!req->locus_list)
		req->locus_list = list_create();
	
	list_prepend(req->locus_list, loc);
}

struct trace_data {
	struct obstack stk;
	char *file;
};

static char *
skip_common_substring(char *str, char *pat)
{
	char *start = str;

	while (*str == *pat++) 
		if (*str++ == '/')
			start = str;
	return start; 
}

static int
_trace_path_compose(void *item, void *data)
{
	LOCUS *loc = item;
	struct trace_data *td = data;
	char buf[64];
	
	if (!td->file) {
		td->file = loc->file;
		obstack_grow(&td->stk, loc->file, strlen(loc->file));
		obstack_1grow(&td->stk, ':');
	} else if (strcmp(td->file, loc->file) == 0) {
		obstack_1grow(&td->stk, ',');
	} else {
		char *p;
		
		obstack_1grow(&td->stk, ';');
		obstack_1grow(&td->stk, ' ');
		
		p = skip_common_substring(loc->file, td->file);
		obstack_grow(&td->stk, p, strlen(p));
		obstack_1grow(&td->stk, ':');
		td->file = loc->file;
	}

	snprintf(buf, sizeof buf, "%lu", (unsigned long) loc->line);
	obstack_grow(&td->stk, buf, strlen(buf));
	
	return 0;
}

void
radius_trace_path(RADIUS_REQ *req)
{
	struct trace_data td;
	char *p;
	
	if (!req->locus_list)
		return; 
	
	obstack_init(&td.stk);
	td.file = NULL;
	list_iterate(req->locus_list, _trace_path_compose, &td);
	p = obstack_finish(&td.stk);
	radlog_req(L_INFO, req, _("rule trace: %s"), p);
	obstack_free(&td.stk, NULL);
}
