/* This file is part of GNU Radius.
   Copyright (C) 2002,2003 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_RADPDU_C

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
#include <radius.h>
#include <obstack1.h>


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

void rad_pdu_destroy(struct radius_pdu *pdu);
int rad_attr_write(struct radius_attr *ap, void *data, size_t size);
int rad_encode_pair(struct radius_attr *ap, VALUE_PAIR *pair);


/* Initialize a PDU */
static void
rad_pdu_init(struct radius_pdu *pdu)
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
static size_t
rad_pdu_finish(void **ptr, struct radius_pdu *pdu,
	       int code, int id, u_char *vector, u_char *secret)
{
        AUTH_HDR *hdr;
        void *p;
        size_t secretlen = 0;
        size_t len = sizeof(AUTH_HDR) + pdu->size;
        u_char digest[AUTH_DIGEST_LEN];
        
	if (code != RT_AUTHENTICATION_REQUEST) {
                secretlen = strlen(secret);
                obstack_grow(&pdu->st, secret, secretlen);
        }
        /* Create output array */
        p = obstack_finish(&pdu->st);
        hdr = emalloc(len + secretlen);
        hdr->code = code;
        hdr->id = id;
        hdr->length = htons(len);
     
        memcpy(hdr + 1, p, pdu->size + secretlen);

	/* Seal the message properly. Note that the secret has already been
	   appended to the pdu wherever necessary */
	switch (code) {
	case RT_AUTHENTICATION_REQUEST:
		memcpy(hdr->vector, vector, AUTH_VECTOR_LEN);
		break;
		
	case RT_ACCOUNTING_REQUEST:
		/* For an accounting request, we need to calculate
		   the md5 hash over the entire packet and put it in the
		   vector. */
                secretlen = strlen(secret);
                md5_calc(hdr->vector, (u_char *)hdr, len + secretlen);
		memcpy(vector, hdr->vector, AUTH_VECTOR_LEN);
                memset((char*)hdr + len, 0, secretlen);
		break;
		
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCESS_CHALLENGE:
		memcpy(hdr->vector, vector, AUTH_VECTOR_LEN);
		/*FALL THROUGH*/
		
	default:
		/* This is a reply message. Calculate the response digest
		   and store it in the pdu */
		md5_calc(digest, (u_char *)hdr, len + secretlen);
		memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
		memset((char*)hdr + len, 0, secretlen);
		break;
	}

        *ptr = hdr;
        return len;
}

/* Destroy the PDU */
void 
rad_pdu_destroy(struct radius_pdu *pdu)
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
rad_attr_write(struct radius_attr *ap, void *data, size_t size)
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
rad_encode_pair(struct radius_attr *ap, VALUE_PAIR *pair)
{
        UINT4 lval;
        size_t len;
        int rc;

        switch (pair->type) {
        case TYPE_STRING:
                /* Do we need it? */
                if (pair->avp_strlength == 0 && pair->avp_strvalue[0] != 0)
                        pair->avp_strlength = strlen(pair->avp_strvalue);

                len = pair->avp_strlength;
                if (len > AUTH_STRING_LEN) 
                        len = AUTH_STRING_LEN;
                rc = rad_attr_write(ap, pair->avp_strvalue, len);
                break;
                
        case TYPE_INTEGER:
        case TYPE_IPADDR:
                lval = htonl(pair->avp_lvalue);
                rc = rad_attr_write(ap, &lval, sizeof(UINT4));
                break;

        default:
                radlog(L_ERR, "Unknown pair type %d", pair->type);
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
rad_create_pdu(void **rptr, int code, int id, u_char *vector,
	       u_char *secret, VALUE_PAIR *pairlist, char *msg)
{
        struct radius_pdu pdu;
        size_t attrlen = 0;
        int status = 0;
        int len;
        VALUE_PAIR *pair;
        
        rad_pdu_init(&pdu);

        for (pair = pairlist; pair; pair = pair->next) {
                struct radius_attr attr;
                UINT4 lval;
                int vendorcode, vendorpec;
                
                if (debug_on(10)) {
                        char *save;
                        radlog(L_DEBUG,
                               "send: %s", format_pair(pair, &save));
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
                        attr.data[5] = 2+attrlen; /* Fill in the length */
                } else if (pair->attribute > 0xff)
                        continue;
		else {
			attr.attrno = pair->attribute;
			attrlen = rad_encode_pair(&attr, pair);
		}
                if (attrlen < 0) {
                        radlog(L_ERR, "attrlen = %d", attrlen);
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

                while (len > 0) {
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
			debug(10,("send: Reply-Message = %*.*s",
				  block_len, block_len, attr.data));
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

static VALUE_PAIR *
rad_decode_pair(UINT4 attrno, char *ptr, size_t attrlen)
{
        DICT_ATTR *attr;
        VALUE_PAIR *pair;
        UINT4 lval;
        
        if ((attr = attr_number_to_dict(attrno)) == NULL) {
                debug(1, ("Received unknown attribute %d", attrno));
                return NULL;
        }

        if ( attrlen > AUTH_STRING_LEN ) {
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
                /* attrlen always <= AUTH_STRING_LEN */
                pair->avp_strlength = attrlen;
                pair->avp_strvalue = emalloc(attrlen + 1);
                memcpy(pair->avp_strvalue, ptr, attrlen);
                pair->avp_strvalue[attrlen] = 0;

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
                pair->avp_lvalue = ntohl(lval);

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

static int
decode_vsa(u_char *ptr, UINT4 attrlen, UINT4 *vendorpec, UINT4 *vendorcode)
{
	UINT4 x;
	
	if (attrlen <= 6) { /*FIXME*/
		radlog(L_NOTICE,
		       _("Received a vendor-specific attribute with length <= 6"));
		return 1;
	}
	memcpy(&x, ptr, 4);
	*vendorpec = ntohl(x);
	*vendorcode = vendor_pec_to_id(*vendorpec);

	return *vendorcode == 0;
}

/* Receive UDP client requests, build an authorization request
   structure, and attach attribute-value pairs contained in the request
   to the new structure. */

RADIUS_REQ *
rad_decode_pdu(UINT4 host, u_short udp_port, u_char *buffer, size_t length)
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
                       _("Actual request length does not match reported length (%d, %d)"),
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

        /* Extract attribute-value pairs  */
        ptr = (u_char*) (auth + 1);
        first_pair = NULL;
        prev = NULL;
        endp = (u_char*)auth + length;
        stop = 0;
        
        while (ptr < endp && !stop) {
                UINT4 attrno, attrlen, vendorcode, vendorpec;
                                
                attrno = *ptr++;
                attrlen = *ptr++;
                if (attrlen < 2) {
			debug(1,("exit from the loop"));
                        stop = 1;
                        continue;
                }
                attrlen -= 2;
                length  -= 2;
                
                if (attrno == DA_VENDOR_SPECIFIC
		    && decode_vsa(ptr, attrlen, &vendorpec, &vendorcode) == 0) {
                        ptr += 4;
                        attrlen -= 4;

                        while (attrlen > 0) {
                                size_t len;

				if (vendorpec == 429) {
					/* Hack for non-compliant USR VSA */
					memcpy(&attrno, ptr, 4);
					attrno = ntohl(attrno)
						 | (vendorcode << 16);
					ptr += 4;
					attrlen -= 4;
					len = attrlen;
				} else {
					attrno = *ptr++ | (vendorcode << 16);
					len = *ptr++ - 2;
				}
				
                                pair = rad_decode_pair(attrno, ptr, len);
                                if (pair) {
                                	if (first_pair == NULL) 
                                        	first_pair = pair;
                                	else 
                                        	prev->next = pair;
                                	prev = pair;
				} 
                                ptr += len;
                                attrlen -= len + 2;
                        }
                } else {
                        pair = rad_decode_pair(attrno, ptr, attrlen);
                        ptr += attrlen;
                        if (pair) {
                        	if (first_pair == NULL) 
                                	first_pair = pair;
                        	else 
                                	prev->next = pair;
                        	prev = pair;
			}
                }
        }

	/* Add NAS-IP-Address if the NAS didn't send one */
	if (!avl_find(first_pair, DA_NAS_IP_ADDRESS)) 
		avl_add_pair(&first_pair,
			     avp_create_integer(DA_NAS_IP_ADDRESS, host));
	
        radreq->request = first_pair;
#ifdef DEBUG_ONLY
        {
                VALUE_PAIR *p = avl_find(radreq->request, DA_NAS_IP_ADDRESS);
                if (p)
                        radreq->ipaddr = p->avp_lvalue;
        }
#endif
        return radreq;
}

