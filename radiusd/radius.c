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

#define RADIUS_MODULE_RADIUS_C
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
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <radiusd.h>
#include <obstack1.h>

#undef DEBUG_ONLY 

/* Structure for building radius PDU. */
struct radius_pdu {
	size_t size;        /* Size of the data, collected so far */
	struct obstack st;  /* Data buffer */
};

/* Structure for building single attribute */
struct radius_attr {
	u_char attrno;       /* Attribute number */
	u_char length;       /* Length of the data collected so far */
	u_char data[AUTH_STRING_LEN];    
};

static size_t rad_create_pdu(void **rptr, int code, int id,
			     u_char *vector, u_char *secret,
			     VALUE_PAIR *pairlist, char *msg);
static int rad_pdu_init(struct radius_pdu *pdu);
static VALUE_PAIR *rad_decode_pair(int attrno, char *ptr, int attrlen);
size_t rad_pdu_finish(void **ptr, struct radius_pdu *pdu, int code,
		      int id, u_char *vector, u_char *secret);
size_t rad_pdu_finish_request(void **ptr, struct radius_pdu *pdu,
			      int code,	int id,	u_char *vector,
			      u_char *secret);

void * rad_pdu_destroy(struct radius_pdu *pdu);
int rad_attr_write(struct radius_attr *ap, void *data, size_t size);
int rad_encode_pair(struct radius_attr *ap, VALUE_PAIR *pair);


/* Initialize a PDU */
int
rad_pdu_init(pdu)
	struct radius_pdu *pdu;
{
	pdu->size = 0;
	obstack_init(&pdu->st);
}

/* Finalize the PDU.
   Input: pdu    -- PDU structure.
          code   -- Reply code.
	  id     -- Request ID.
	  vector -- Request authenticator.
   Output:
          *ptr   -- Radius reply.
   Return value: length of the data on *ptr. */	  
size_t
rad_pdu_finish(ptr, pdu, code, id, vector, secret)
	void **ptr;
	struct radius_pdu *pdu;
	int code;
	int id;
	u_char *vector;
	u_char *secret;
{
	AUTH_HDR *hdr;
	void *p;
	size_t secretlen = strlen(secret);
	size_t len = sizeof(AUTH_HDR) + pdu->size;
	u_char digest[AUTH_DIGEST_LEN];
	
	obstack_grow(&pdu->st, secret, secretlen);

	/* Create output array */
	p = obstack_finish(&pdu->st);
	hdr = emalloc(len + secretlen);
        hdr->code = code;
        hdr->id = id;
        memcpy(hdr->vector, vector, AUTH_VECTOR_LEN);
	hdr->length = htons(len);

	memcpy(hdr + 1, p, pdu->size + secretlen);
	
	/* Calculate the response digest */
	md5_calc(digest, (u_char *)hdr, len + secretlen);
	memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
	memset((char*)hdr + len, 0, secretlen);
	*ptr = hdr;
	return len;
}

/* Finalize the PDU.
   Input: pdu    -- PDU structure.
          code   -- Reply code.
	  id     -- Request ID.
	  vector -- Request authenticator.
   Output:
          *ptr   -- Radius reply.
   Return value: length of the data on *ptr. */	  
size_t
rad_pdu_finish_request(ptr, pdu, code, id, vector, secret)
	void **ptr;
	struct radius_pdu *pdu;
	int code;
	int id;
	u_char *vector;
	u_char *secret;
{
	AUTH_HDR *hdr;
	void *p;
	size_t secretlen = 0;
	size_t len = sizeof(AUTH_HDR) + pdu->size;
	u_char digest[AUTH_DIGEST_LEN];
	
	if (code == RT_AUTHENTICATION_REQUEST) {
		secretlen = strlen(secret);
		obstack_grow(&pdu->st, secret, secretlen);
	}
	/* Create output array */
	p = obstack_finish(&pdu->st);
	hdr = emalloc(len + secretlen);
        hdr->code = code;
        hdr->id = id;
	hdr->length = htons(len);
	if (code == RT_AUTHENTICATION_REQUEST) 
                memcpy(hdr->vector, vector, AUTH_VECTOR_LEN);

	memcpy(hdr + 1, p, pdu->size + secretlen);
	
        /* If this is not an authentication request, we need to calculate
           the md5 hash over the entire packet and put it in the vector. */
        if (code != RT_AUTHENTICATION_REQUEST) {
                secretlen = strlen(secret);
		md5_calc(hdr->vector, (u_char *)hdr, len + secretlen);
		memset((char*)hdr + len, 0, secretlen);
	}
	*ptr = hdr;
	return len;
}

/* Destroy the PDU */
void *
rad_pdu_destroy(pdu)
	struct radius_pdu *pdu;
{
	obstack_free(&pdu->st, NULL);
}

/* Append attribute A to the PDU P */
#define rad_pdu_add(p,a) \
 do { obstack_grow(&(p)->st,&(a),(a).length); \
      (p)->size+=(a).length; } while (0)

/* Initialize the attribute structure. */	
#define rad_attr_init(a) (a)->length = 2

/* Append SIZE bytes from DATA to radius_attr AP. */	
int
rad_attr_write(ap, data, size)
	struct radius_attr *ap;
	void *data;
	size_t size;
{
	if (sizeof(ap->data) - ap->length + 2 < size)
		return 0;
	memcpy(ap->data + ap->length - 2, data, size);
	ap->length += size;
	return size;
}

/* Encode a single A/V pair into struct radius_attr.
   Input: ap   -- Target attribute structure.
          pair -- The pair to be encoded.
   Return value: length of the encoded data or 0 if an error occurred */
   
int
rad_encode_pair(ap, pair)
	struct radius_attr *ap;
	VALUE_PAIR *pair;
{
	UINT4 lval;
	size_t len;
	int rc;
	
	switch (pair->type) {
	case TYPE_STRING:
		/* Do we need it? */
		if (pair->strlength == 0 && pair->strvalue[0] != 0)
			pair->strlength = strlen(pair->strvalue);

		len = pair->strlength;
		if (len >= AUTH_STRING_LEN) 
			len = AUTH_STRING_LEN - 1;
		rc = rad_attr_write(ap, pair->strvalue, len);
		break;
		
	case TYPE_INTEGER:
	case TYPE_IPADDR:
		lval = htonl(pair->lvalue);
		rc = rad_attr_write(ap, &lval, sizeof(UINT4));
		break;

	default:
		rc = 0;
	}
	return rc;
}

/* Create a radius PDU.
   Input:  code     -- Radius reply code
           pairlist -- List of A/V pairs to be encoded in the reply
	   msg      -- User message.
   Output: *rptr    -- PDU
   Return value: lenght of the data in *rptr. 0 on error */
   
size_t
rad_create_pdu(rptr, code, id, vector, secret, pairlist, msg)
	void **rptr;
	int code;
	int id;
	u_char *vector;
	u_char *secret;
	VALUE_PAIR *pairlist;
	char *msg;
{
	AUTH_HDR *hdr;
	struct radius_pdu pdu;
	size_t attrlen = 0;
	int status = 0;
	int len;
	VALUE_PAIR *pair;
	
	rad_pdu_init(&pdu);

	for (pair = pairlist; pair; pair = pair->next) {
		struct radius_attr attr;
		u_char *ptr;
		UINT4 lval;
		int vendorcode, vendorpec;
		
                if (debug_on(10)) {
                        char *save;
                        radlog(L_DEBUG,
                               "reply: %s", format_pair(pair, &save));
                        free(save);
                }

		rad_attr_init(&attr);
		if ((vendorcode = VENDOR(pair->attribute)) > 0
		    && (vendorpec  = vendor_id_to_pec(vendorcode)) > 0) {
			u_char c;
			
			attr.attrno = DA_VENDOR_SPECIFIC;
                        lval = htonl(vendorpec);
			rad_attr_write(&attr, &lval, 4);
			c = pair->attribute & 0xff;
			rad_attr_write(&attr, &c, 1); 
			rad_attr_write(&attr, &lval, 1); /* Reserve a byte */
			attrlen = rad_encode_pair(&attr, pair);
			attr.data[5] = attrlen; /* Fill in the reserved byte */
		} else if (pair->attribute <= 0xff) {
			attr.attrno = pair->attribute;
			attrlen = rad_encode_pair(&attr, pair);
		}
		if (attrlen <= 0) {
			status = 1;
			break;
		}
		rad_pdu_add(&pdu, attr);
	}

        /* Append the user message
	   Add multiple DA_REPLY_MESSAGEs if it doesn't fit into one. */
	if (status == 0
	    && msg != NULL
	    && (len = strlen(msg)) > 0) {
                int block_len;
		struct radius_attr attr;
                
                while (attrlen > 0 && len > 0) {
                        if (len > AUTH_STRING_LEN) 
                                block_len = AUTH_STRING_LEN;
			else 
                                block_len = len;

			rad_attr_init(&attr);
			attr.attrno = DA_REPLY_MESSAGE;
			attrlen = rad_attr_write(&attr, msg, block_len);
			if (attrlen <= 0) {
				status = 1;
				break;
			}
			rad_pdu_add(&pdu, attr);
			msg += block_len;
			len -= block_len;
                }
        }

	if (status == 0)
		attrlen = rad_pdu_finish(rptr, &pdu, code, id, vector, secret);
	else
		attrlen = 0;
	rad_pdu_destroy(&pdu);
	return attrlen;
}

/* Build and send a reply to the incoming request.
   Input: code        -- Reply code.
          radreq      -- The request.
	  reply_pairs -- List of A/V pairs to be encoded in the reply
	  msg         -- User message
	  fd          -- Socket descriptor.
    NOTE: If radreq contains cached reply information, this information
          is used instead of the supplied arguments. */

void
rad_send_reply(code, radreq, reply_pairs, msg, fd)
        int code;
        RADIUS_REQ *radreq;
        VALUE_PAIR *reply_pairs;
        char *msg;
        int fd;
{
	void *pdu;
	char *what;
	size_t length;
	
	if (radreq->reply_code == 0) {
		VALUE_PAIR *reply;
		
                /* Save the data */
		radreq->reply_code = code;
		radreq->reply_msg = estrdup(msg);

		reply = avl_dup(reply_pairs);
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

	switch (code) {
	case RT_PASSWORD_REJECT:
	case RT_AUTHENTICATION_REJECT:
		what = _("Reject");
		break;
			
	case RT_ACCESS_CHALLENGE:
		what = _("Challenge");
		stat_inc(auth, radreq->ipaddr, num_challenges);
		break;
			
	case RT_AUTHENTICATION_ACK:
		what = _("Ack");
		break;
		
	case RT_ACCOUNTING_RESPONSE:
		what = _("Accounting Ack");
		break;
			
	default:
		what = _("Reply");
		break;
        }

	length = rad_create_pdu(&pdu, code,
				radreq->id, radreq->vector, radreq->secret,
				radreq->reply_pairs, radreq->reply_msg);
	if (length > 0) {
		struct sockaddr saremote;
		struct sockaddr_in *sin;
		char buf[MAX_LONGNAME];

		debug(1, ("Sending %s of id %d to %lx (nas %s)",
			  what, radreq->id, (u_long)radreq->ipaddr,
			  nas_request_to_name(radreq, buf, sizeof buf)));
		
		sin = (struct sockaddr_in *) &saremote;
		memset ((char *) sin, '\0', sizeof (saremote));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(radreq->ipaddr);
		sin->sin_port = htons(radreq->udp_port);
#ifndef DEBUG_ONLY
		sendto(fd, pdu, length, 0,
		       &saremote, sizeof(struct sockaddr_in));
#endif
		efree(pdu);
	}
}

#ifdef USE_LIVINGSTON_MENUS
/* Reply to the request with a CHALLENGE. Also attach any user message
   provided and a state value.
   Input: radreq      -- The request.
	  msg         -- User message.
	  state       -- Value of the State attribute.
	  fd          -- Socket descriptor. */
void
send_challenge(radreq, msg, state, fd)
        RADIUS_REQ *radreq;
        char *msg;
        char *state;
        int fd;
{
	void *pdu;
	size_t length;
	VALUE_PAIR *p = avp_create(DA_STATE, 0, state, 0);

	length = rad_create_pdu(&pdu, RT_ACCESS_CHALLENGE, radreq->id,
				radreq->vector, radreq->secret, p, msg);
	if (length > 0) {
		struct sockaddr saremote;
		struct sockaddr_in *sin;
		char buf[MAX_LONGNAME];

		debug(1, ("Sending Challenge of id %d to %lx (nas %s)",
			  radreq->id, (u_long)radreq->ipaddr,
			  nas_request_to_name(radreq, buf, sizeof buf)));
        
		stat_inc(auth, radreq->ipaddr, num_challenges);
        
		sin = (struct sockaddr_in *) &saremote;
		memset ((char *) sin, '\0', sizeof (saremote));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(radreq->ipaddr);
		sin->sin_port = htons(radreq->udp_port);

#ifndef DEBUG_ONLY
		sendto(fd, pdu, length, 0,
		       &saremote, sizeof(struct sockaddr_in));
#endif
		efree(pdu);
	}
	avp_free(p);
}
#endif

/* Validates the requesting client NAS. */
int
validate_client(radreq)
        RADIUS_REQ *radreq;
{
        CLIENT  *cl;
        char buf[MAX_LONGNAME];
        
        if ((cl = client_lookup_ip(radreq->ipaddr)) == NULL) {
                radlog(L_ERR, _("request from unknown client: %s"),
                       client_lookup_name(radreq->ipaddr, buf, sizeof buf));
                return -1;
        }

        /* Save the secret key */
        radreq->secret = cl->secret;

        return 0;
}

/* Validates the requesting NAS */
int
calc_acctdigest(radreq)
        RADIUS_REQ *radreq;
{
        int     secretlen;
        char zero[AUTH_VECTOR_LEN];
        u_char  *recvbuf;
        int     len = radreq->data_len;
        u_char digest[AUTH_VECTOR_LEN];

        secretlen = strlen(radreq->secret);

        recvbuf = emalloc(len + secretlen);
        memcpy(recvbuf, radreq->data, len + secretlen);
        
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

/*
 *      Receive UDP client requests, build an authorization request
 *      structure, and attach attribute-value pairs contained in
 *      the request to the new structure.
 */
RADIUS_REQ *
radrecv(host, udp_port, buffer, length)
        UINT4 host;
        u_short udp_port;
        u_char *buffer;
        int length;
{
        u_char          *ptr;
        AUTH_HDR        *auth;
        VALUE_PAIR      *first_pair;
        VALUE_PAIR      *prev;
        VALUE_PAIR      *pair;
        RADIUS_REQ      *radreq;
	UINT4 reported_len;
	u_char *endp;
	int stop;
	
        radreq = radreq_alloc();
        debug(1,("allocated radreq: %p",radreq));

        auth = (AUTH_HDR *)buffer;
	reported_len = ntohs(auth->length);
	if (length > reported_len) { /* FIXME: != ? */
                radlog(L_WARN,
                       _("Received message length > packet length (%d, %d)"),
		       length, reported_len);
                length = reported_len;
        }
                
        debug(1, ("Request from host %lx code=%d, id=%d, length=%d",
                                (u_long)host, auth->code, auth->id,
		  ntohs(auth->length)));

        /*
         *      Fill header fields
         */
        radreq->ipaddr = host;
        radreq->udp_port = udp_port;
        radreq->id = auth->id;
        radreq->code = auth->code;
        memcpy(radreq->vector, auth->vector, AUTH_VECTOR_LEN);
        radreq->data = buffer;
        radreq->data_len = length;

        /* Extract attribute-value pairs  */
        ptr = (u_char*) (auth + 1);
        first_pair = NULL;
        prev = NULL;
	endp = (u_char*)auth + length;
	stop = 0;
	
	while (ptr < endp && !stop) {
		UINT4 attrno, attrlen, lval, vendorcode, vendorpec;
				
                attrno = *ptr++;
                attrlen = *ptr++;
                if (attrlen < 2) {
			stop = 1;
                        continue;
                }
                attrlen -= 2;
                length  -= 2;
		
                if (attrno == DA_VENDOR_SPECIFIC) {
			if (attrlen <= 6) { /*FIXME*/
				stop = 1;
				continue;
			}
                        memcpy(&lval, ptr, 4);
                        vendorpec = ntohl(lval);
                        if ((vendorcode = vendor_pec_to_id(vendorpec)) == 0) {
				stop = 1;
				continue;
			}
			
			ptr += 4;
			attrlen -= 4;
			while (attrlen > 0) {
				UINT4 len;
				attrno = *ptr++ | (vendorcode << 16);
				len = *ptr++ - 2;
				pair = rad_decode_pair(attrno, ptr, len);
				if (!pair) {
					stop = 1;
					break;
				}
				if (first_pair == NULL) 
					first_pair = pair;
				else 
					prev->next = pair;
				prev = pair;
				ptr += len;
                                attrlen -= len + 2;
                        }
                } else {
			pair = rad_decode_pair(attrno, ptr, attrlen);
			ptr += attrlen;
			if (!pair) {
				stop = 1;
				break;
			}
			if (first_pair == NULL) 
				first_pair = pair;
			else 
				prev->next = pair;
			prev = pair;
		}
	}

        radreq->request = first_pair;
#ifdef DEBUG_ONLY
        {
                VALUE_PAIR *p = avl_find(radreq->request, DA_NAS_IP_ADDRESS);
                if (p)
                        radreq->ipaddr = p->lvalue;
        }
#endif
        return radreq;
}

VALUE_PAIR *
rad_decode_pair(attrno, ptr, attrlen)
	int attrno;
	char *ptr;
	int attrlen;
{
	DICT_ATTR *attr;
	VALUE_PAIR *pair;
	UINT4 lval;
	
	if ((attr = attr_number_to_dict(attrno)) == NULL) {
		debug(1, ("Received unknown attribute %d", attrno));
		return NULL;
	}

	if ( attrlen >= AUTH_STRING_LEN ) {
		debug(1, ("attribute %d too long, %d >= %d", attrno,
			  attrlen, AUTH_STRING_LEN));
		return NULL;
	}

	pair = avp_alloc();
	
	pair->name = attr->name;
	pair->attribute = attr->value;
	pair->type = attr->type;
	pair->prop = attr->prop;
	pair->next = NULL;

	switch (attr->type) {

	case TYPE_STRING:
		/* attrlen always < AUTH_STRING_LEN */
		pair->strlength = attrlen;
		pair->strvalue = alloc_string(attrlen + 1);
		memcpy(pair->strvalue, ptr, attrlen);
		pair->strvalue[attrlen] = 0;

		if (debug_on(10)) {
			char *save;
			radlog(L_DEBUG, "recv: %s",
			       format_pair(pair, &save));
			free(save);
		}

		break;
                        
	case TYPE_INTEGER:
	case TYPE_IPADDR:
		memcpy(&lval, ptr, sizeof(UINT4));
		pair->lvalue = ntohl(lval);

		if (debug_on(10)) {
			char *save;
			radlog(L_DEBUG, 
			       "recv: %s", 
			       format_pair(pair, &save));
			free(save);
		}
		break;
                        
	default:
		debug(1, ("    %s (Unknown Type %d)",
			  attr->name,attr->type));
		avp_free(pair);
		pair = NULL;
		break;
	}
	
	return pair;
}
