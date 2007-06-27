/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001,2003,2004,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>

int
snmp_send(struct snmp_session *sess, struct snmp_pdu *pdu)
{
        struct snmp_request *req;
            
        /* if the session isn't initialized do it now */
        if (sess->sd == -1 &&
            snmp_session_open(sess, 0, 0, 0, 0))
                return -1;

        switch (pdu->type) {
        case SNMP_PDU_GET:
        case SNMP_PDU_GETNEXT:
        case SNMP_PDU_RESPONSE:
        case SNMP_PDU_SET:
                if (pdu->req_id == 0)
                        pdu->req_id = snmp_req_id();
                break;
        default:
                abort();
        }

        req = snmp_alloc(sizeof(*req));
        if (!req) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                snmp_pdu_free(pdu); /*FIXME?*/
                return -1;
        }
        req->next = sess->request_list;
        sess->request_list = req;
        
        req->retries = 1;
        req->timeout = sess->timeout;
        req->pdu = pdu;
        return snmp_request_xmit(sess, req);
}

int
snmp_request_xmit(struct snmp_session *sess, struct snmp_request *req)
{
        u_char packet_buf[SNMP_PACKET_LENGTH];
        int length;
        struct timeval tv;

        length = sizeof(packet_buf);
        if (snmp_encode_request(sess, req->pdu, packet_buf, &length)) 
                return -1;

        gettimeofday(&tv, (struct timezone *) 0);
        if (sendto(sess->sd, (char *) packet_buf, length, 0,
                   (struct sockaddr *) &sess->remote_sin,
                   sizeof(sess->remote_sin)) < 0) {
                SNMP_SET_ERRNO(E_SNMP_SEND);
                return -1;
        }

        tv.tv_usec += req->timeout;
        tv.tv_sec += tv.tv_usec / 1000000L;
        tv.tv_usec %= 1000000L;
        req->expire = tv;

        return 0;
}

/* As per RFCs 1901, 1157:
   Message ::=
     SEQUENCE {
       version   INTEGER
       community OCTET STRING
       data
     } */

int
snmp_encode_request(struct snmp_session *sess, struct snmp_pdu *pdu,
		    u_char *packet_buf, int *length)
{
        u_char *buf, *msg_start, *pdu_header_ptr, *pdu_data_start,
               *var_header_ptr, *var_data_start;
        
        #define BAIL_OUT if (!buf) return -1
        
        buf = packet_buf;
        buf = asn_encode_header(buf, length,
                                (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0xffff);
        BAIL_OUT;
        
        msg_start = buf;
        /* version */
        buf = asn_encode_int(buf, length,
                             (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             sess->version);
        BAIL_OUT;

        /* community */
        buf = asn_encode_string(buf, length,
                               (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                                sess->community.str,
                                sess->community.len);
        BAIL_OUT;

        /* data */
        pdu_header_ptr = buf;
        buf = asn_encode_header(buf, length, pdu->type, 0xffff);
        BAIL_OUT;

        pdu_data_start = buf;
        buf = snmp_pdu_encode(buf, length, pdu);
        BAIL_OUT;
        
        var_header_ptr = buf;
        buf = asn_encode_header(buf, length,
                                (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                0xffff);
        BAIL_OUT;

        var_data_start = buf;
        buf = snmp_var_encode(buf, length, pdu->var, sess->version);

        /* Fixup lengths */
        asn_recode_length(pdu_header_ptr+1,
                          (int) (buf - pdu_data_start));
        asn_recode_length(packet_buf+1,
                          (int)(buf-msg_start));
        asn_recode_length(var_header_ptr+1,
                          (buf-var_data_start));
        *length = buf - packet_buf;
        return 0;
}

int
snmp_decode_request(struct snmp_session *sess, struct snmp_pdu *pdu,
		    u_char *packet, int length, char *comm, int *comm_len)
{
        int vers;
        u_char *buf;
        u_char type;

        buf = asn_decode_header(packet, &length, &type);
        if (!buf) 
                return -1;
        if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
                SNMP_SET_ERRNO(E_SNMP_DECODE);
                return -1;
        }

        buf = asn_decode_int(buf, &length, &type, &vers, sizeof(vers));
        if (!buf)
                return -1;

        buf = asn_decode_string(buf, &length, &type, comm, comm_len);
        if (!buf)
                return -1;

        comm[*comm_len] = 0;
        
        if (vers != SNMP_VERSION_1) {
                SNMP_SET_ERRNO(E_SNMP_BAD_VERSION);
                return -1;
        }
        buf = snmp_pdu_decode(buf, &length, pdu);
        if (!buf)
                return -1;

        buf = snmp_var_decode(buf, &length, &pdu->var, vers);
        if (!buf)
                return -1;

        return 0;
}
