/* This file is part of GNU Radius.
   Copyright (C) 2002,2003,2004,2006,2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

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

#include <radlib.h>

/* Structure for building radius PDU. */
struct radius_pdu {
        grad_slist_t slist;  /* Data buffer */
};

/* Structure for building single attribute */
struct radius_attr {
        u_char attrno;       /* Attribute number */
        u_char length;       /* Length of the data collected so far */
        u_char data[GRAD_STRING_LENGTH];    
};

void grad_pdu_destroy(struct radius_pdu *pdu);
int grad_attr_write(struct radius_attr *ap, void *data, size_t size);
int grad_encode_pair(struct radius_attr *ap, grad_avp_t *pair);


/* Initialize a PDU */
static void
grad_pdu_init(struct radius_pdu *pdu)
{
        pdu->slist = grad_slist_create();
}

/* Finalize the PDU.
   Input: pdu    -- PDU structure.
          code   -- Reply code.
          id     -- Request ID.
          authenticator -- Request authenticator.
   Output:
          *ptr   -- Radius reply.
   Return value: length of the data on *ptr. */
static size_t
grad_pdu_finish(void **ptr, struct radius_pdu *pdu,
		int code, int id, u_char *authenticator, u_char *secret)
{
        grad_packet_header_t *hdr;
        void *p;
        size_t secretlen = 0;
        size_t size = grad_slist_size(pdu->slist);
        size_t len = sizeof(grad_packet_header_t) + size;
        u_char digest[GRAD_MD5_DIGEST_LENGTH];
	
	if (code != RT_ACCESS_REQUEST && code != RT_STATUS_SERVER) {
                secretlen = strlen(secret);
                grad_slist_append(pdu->slist, secret, secretlen);
        }
        /* Create output array */
        p = grad_slist_finish(pdu->slist);
        hdr = grad_emalloc(len + secretlen);
        hdr->code = code;
        hdr->id = id;
        hdr->length = htons(len);
     
        memcpy(hdr + 1, p, size + secretlen);

	/* Seal the message properly. Note that the secret has already been
	   appended to the pdu wherever necessary */
	switch (code) {
	case RT_ACCESS_REQUEST:
	case RT_STATUS_SERVER:
		memcpy(hdr->authenticator, authenticator, GRAD_AUTHENTICATOR_LENGTH);
		break;
		
	case RT_ACCOUNTING_REQUEST:
		/* For an accounting request, we need to calculate
		   the md5 hash over the entire packet and put it in the
		   authenticator. */
                secretlen = strlen(secret);
                grad_md5_calc(hdr->authenticator, (u_char *)hdr, len + secretlen);
		memcpy(authenticator, hdr->authenticator, GRAD_AUTHENTICATOR_LENGTH);
                memset((char*)hdr + len, 0, secretlen);
		break;
		
	case RT_ACCESS_ACCEPT:
	case RT_ACCESS_REJECT:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCESS_CHALLENGE:
		memcpy(hdr->authenticator, authenticator, GRAD_AUTHENTICATOR_LENGTH);
		/*FALL THROUGH*/
		
	default:
		/* This is a reply message. Calculate the response digest
		   and store it in the pdu */
		grad_md5_calc(digest, (u_char *)hdr, len + secretlen);
		memcpy(hdr->authenticator, digest, GRAD_AUTHENTICATOR_LENGTH);
		memset((char*)hdr + len, 0, secretlen);
		break;
	}

        *ptr = hdr;
        return len;
}

/* Destroy the PDU */
void 
grad_pdu_destroy(struct radius_pdu *pdu)
{
	grad_slist_free(&pdu->slist);
}

/* Append attribute A to the PDU P */
#define grad_pdu_add(p,a) \
 grad_slist_append((p)->slist, &(a),(a).length)

/* Initialize the attribute structure. */       
#define grad_attr_init(a) (a)->length = 2

/* Append SIZE bytes from DATA to radius_attr AP. */    
int
grad_attr_write(struct radius_attr *ap, void *data, size_t size)
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
grad_encode_pair(struct radius_attr *ap, grad_avp_t *pair)
{
        grad_uint32_t lval;
        size_t len;
        int rc;

        switch (pair->type) {
        case GRAD_TYPE_STRING:
                /* Do we need it? */
                if (pair->avp_strlength == 0 && pair->avp_strvalue[0] != 0)
                        pair->avp_strlength = strlen(pair->avp_strvalue);

                len = pair->avp_strlength;
                if (len > GRAD_STRING_LENGTH) 
                        len = GRAD_STRING_LENGTH;
                rc = grad_attr_write(ap, pair->avp_strvalue, len);
                break;
                
        case GRAD_TYPE_INTEGER:
        case GRAD_TYPE_IPADDR:
                lval = htonl(pair->avp_lvalue);
                rc = grad_attr_write(ap, &lval, sizeof(grad_uint32_t));
                break;

        default:
                grad_log(GRAD_LOG_ERR, "Unknown pair type %d", pair->type);
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
grad_create_pdu(void **rptr, int code, int id, u_char *authenticator,
		u_char *secret, grad_avp_t *pairlist, char *msg)
{
        struct radius_pdu pdu;
        size_t attrlen = 0;
        int status = 0;
        int len;
        grad_avp_t *pair;
        
        grad_pdu_init(&pdu);

        for (pair = pairlist; pair; pair = pair->next) {
                struct radius_attr attr;
                grad_uint32_t lval;
                int vendorcode, vendorpec;
                
                if (GRAD_DEBUG_LEVEL(10)) {
                        char *save;
                        grad_log(GRAD_LOG_DEBUG,
                                 "send: %s", grad_format_pair(pair, 1, &save));
                        free(save);
                }

                grad_attr_init(&attr);
                if ((vendorcode = GRAD_VENDOR_CODE(pair->attribute)) > 0
                    && (vendorpec  = grad_vendor_id_to_pec(vendorcode)) > 0) {
                        attr.attrno = DA_VENDOR_SPECIFIC;
                        lval = htonl(vendorpec);
                        grad_attr_write(&attr, &lval, 4);
			if (vendorpec == 429) {
				/* Hack for non-compliant USR VSA */
				grad_uint32_t atval = htonl(pair->attribute & 0xffff);
				grad_attr_write(&attr, &atval, 4);
				attrlen = grad_encode_pair(&attr, pair);
			} else {
				u_char c = pair->attribute & 0xff;
				grad_attr_write(&attr, &c, 1);
				/* Reserve a length byte */
				grad_attr_write(&attr, &lval, 1); 
				attrlen = grad_encode_pair(&attr, pair);
				/* Fill in the length */
				attr.data[5] = 2+attrlen; 
			}
                } else if (pair->attribute > 0xff)
                        continue;
		else {
			attr.attrno = pair->attribute;
			attrlen = grad_encode_pair(&attr, pair);
		}
                if (attrlen < 0) {
                        grad_log(GRAD_LOG_ERR, "attrlen = %d", attrlen);
                        status = 1;
                        break;
                }
                grad_pdu_add(&pdu, attr);
        }

        /* Append the user message
           Add multiple DA_REPLY_MESSAGEs if it doesn't fit into one. */
        if (status == 0
            && msg != NULL
            && (len = strlen(msg)) > 0) {
                int block_len;
                struct radius_attr attr;

                while (len > 0) {
                        if (len > GRAD_STRING_LENGTH) 
                                block_len = GRAD_STRING_LENGTH;
                        else 
                                block_len = len;

                        grad_attr_init(&attr);
                        attr.attrno = DA_REPLY_MESSAGE;
                        attrlen = grad_attr_write(&attr, msg, block_len);
                        if (attrlen <= 0) {
                                status = 1;
                                break;
                        }
			GRAD_DEBUG3(10,"send: Reply-Message = %*.*s",
				  block_len, block_len, attr.data);
                        grad_pdu_add(&pdu, attr);
                        msg += block_len;
                        len -= block_len;
                }
        }

        if (status == 0) 
		attrlen = grad_pdu_finish(rptr, &pdu, code, id, authenticator, secret);
	else
                attrlen = 0;
        grad_pdu_destroy(&pdu);
        return attrlen;
}

static grad_avp_t *
grad_decode_pair(grad_uint32_t attrno, char *ptr, size_t attrlen)
{
        grad_dict_attr_t *attr;
        grad_avp_t *pair;
        grad_uint32_t lval;
        
        if ((attr = grad_attr_number_to_dict(attrno)) == NULL) {
                GRAD_DEBUG1(1, "Received unknown attribute %d", attrno);
                return NULL;
        }

        if ( attrlen > GRAD_STRING_LENGTH ) {
                GRAD_DEBUG3(1, "attribute %d too long, %d >= %d", attrno,
                            attrlen, GRAD_STRING_LENGTH);
                return NULL;
        }

        pair = grad_avp_alloc();
        
        pair->name = attr->name;
        pair->attribute = attr->value;
        pair->type = attr->type;
        pair->prop = attr->prop;
        pair->next = NULL;

        switch (attr->type) {

        case GRAD_TYPE_STRING:
                /* attrlen always <= GRAD_STRING_LENGTH */
                pair->avp_strlength = attrlen;
                pair->avp_strvalue = grad_emalloc(attrlen + 1);
                memcpy(pair->avp_strvalue, ptr, attrlen);
                pair->avp_strvalue[attrlen] = 0;

                if (GRAD_DEBUG_LEVEL(10)) {
                        char *save;
                        grad_log(GRAD_LOG_DEBUG, "recv: %s",
                                 grad_format_pair(pair, 1, &save));
                        free(save);
                }

                break;
                        
        case GRAD_TYPE_INTEGER:
        case GRAD_TYPE_IPADDR:
                memcpy(&lval, ptr, sizeof(grad_uint32_t));
                pair->avp_lvalue = ntohl(lval);

                if (GRAD_DEBUG_LEVEL(10)) {
                        char *save;
                        grad_log(GRAD_LOG_DEBUG, 
                                 "recv: %s", 
                                 grad_format_pair(pair, 1, &save));
                        free(save);
                }
                break;
                        
        default:
                GRAD_DEBUG2(1, "%s (Unknown Type %d)", attr->name,attr->type);
                grad_avp_free(pair);
                pair = NULL;
                break;
        }
        
        return pair;
}

static int
decode_vsa(u_char *ptr, grad_uint32_t attrlen, grad_uint32_t *vendorpec, grad_uint32_t *vendorcode)
{
	grad_uint32_t x;
	
	if (attrlen < 6) { /*FIXME*/
		grad_log(GRAD_LOG_NOTICE,
		    _("Received a vendor-specific attribute with length < 6"));
		return 1;
	}
	memcpy(&x, ptr, 4);
	*vendorpec = ntohl(x);
	*vendorcode = grad_vendor_pec_to_id(*vendorpec);

	return *vendorcode == 0;
}

/* Receive UDP client requests, build an authorization request
   structure, and attach attribute-value pairs contained in the request
   to the new structure. */

grad_request_t *
grad_decode_pdu(grad_uint32_t host, u_short udp_port, u_char *buffer, size_t length)
{
        u_char          *ptr;
        grad_packet_header_t        *auth;
        grad_avp_t      *first_pair;
        grad_avp_t      *prev;
        grad_avp_t      *pair;
        grad_request_t  *radreq;
        grad_uint32_t reported_len;
        u_char *endp;
        int stop;
        
        radreq = grad_request_alloc();
        GRAD_DEBUG1(1,"allocated radreq: %p",radreq);
	
        auth = (grad_packet_header_t *)buffer;
        reported_len = ntohs(auth->length);
        if (length > reported_len) { /* FIXME: != ? */
                grad_log(GRAD_LOG_WARN,
             _("Actual request length does not match reported length (%d, %d)"),
                         length, reported_len);
                length = reported_len;
        }
                
        GRAD_DEBUG4(1, "%s from %s, id=%d, length=%d",
		  grad_request_code_to_name(auth->code),
		  grad_ip_iptostr(host, NULL),
		  auth->id,
                  ntohs(auth->length));

        /*
         *      Fill header fields
         */
        radreq->ipaddr = host;
        radreq->udp_port = udp_port;
        radreq->id = auth->id;
        radreq->code = auth->code;
        memcpy(radreq->authenticator, auth->authenticator, GRAD_AUTHENTICATOR_LENGTH);

        /* Extract attribute-value pairs  */
        ptr = (u_char*) (auth + 1);
        first_pair = NULL;
        prev = NULL;
        endp = (u_char*)auth + length;
        stop = 0;
        
        while (ptr < endp && !stop) {
                grad_uint32_t attrno, attrlen, vendorcode, vendorpec;
                                
                attrno = *ptr++;
                attrlen = *ptr++;
                if (attrlen < 2) {
			GRAD_DEBUG(1,"exit from the loop");
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
					attrno = GRAD_VSA_ATTR_NUMBER(
						          ntohl(attrno),
							  vendorcode);
					ptr += 4;
					attrlen -= 4;
					len = attrlen;
					attrlen = 0;
				} else {
					attrno = GRAD_VSA_ATTR_NUMBER(*ptr++,
								   vendorcode);
					len = *ptr++ - 2;
					attrlen -= len + 2;
				}
				
                                pair = grad_decode_pair(attrno, ptr, len);
                                if (pair) {
                                	if (first_pair == NULL) 
                                        	first_pair = pair;
                                	else 
                                        	prev->next = pair;
                                	prev = pair;
				} 
                                ptr += len;
                        }
                } else {
                        pair = grad_decode_pair(attrno, ptr, attrlen);
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

        radreq->avlist = first_pair;
#ifdef DEBUG_ONLY
        {
                grad_avp_t *p = grad_avl_find(radreq->avlist,
					      DA_NAS_IP_ADDRESS);
                if (p)
                        radreq->ipaddr = p->avp_lvalue;
		else
			radreq->ipaddr = host;
        }
#endif
        return radreq;
}

