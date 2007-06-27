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

struct snmp_pdu *
snmp_pdu_create(int type)
{
        struct snmp_pdu *pdu;

        pdu = snmp_alloc(sizeof(*pdu));

        pdu->type = type;
        pdu->req_id = 0;
        pdu->err_stat = 0;
        pdu->err_ind = 0;
        pdu->var = NULL;
        return pdu;
}

void
snmp_pdu_free(struct snmp_pdu *pdu)
{
        if (!pdu)
                return;
        snmp_var_free_list(pdu->var);
        snmp_free(pdu);
}

void
snmp_pdu_add_var(struct snmp_pdu *pdu, struct snmp_var *var)
{
        var->next = pdu->var;
        pdu->var = var;
}

u_char *
snmp_pdu_decode(u_char *data, int *length, struct snmp_pdu *pdu)
{
        u_char *buf = data;
        u_char type;
        
        buf = asn_decode_header(buf, length, &pdu->type);
        if (!buf)
                return NULL;

        switch (pdu->type) {
        case SNMP_PDU_RESPONSE:
        case SNMP_PDU_GET:
        case SNMP_PDU_GETNEXT:
        case SNMP_PDU_SET:
                buf = asn_decode_int(buf, length, &type,
                                     &pdu->req_id, sizeof(pdu->req_id));
                if (!buf)
                        break;

                buf = asn_decode_int(buf, length, &type,
                                     &pdu->err_stat, sizeof(pdu->err_stat));
                if (!buf)
                        break;
                
                buf = asn_decode_int(buf, length, &type,
                                     &pdu->err_ind, sizeof(pdu->err_ind));
                break;
        default:
                SNMP_SET_ERRNO(E_SNMP_UNKNOWN_REQ);
                buf = NULL;
        }
        return buf;
}
                
                
u_char *
snmp_pdu_encode(u_char *data, int *length, struct snmp_pdu *pdu)
{
        u_char *buf = data;

#define BAIL_OUT if (!buf) return NULL;
        
        /*FIXME: No support for trap and bulk PDUs */
        buf = asn_encode_int(buf, length,
                             (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             pdu->req_id);
        BAIL_OUT;

        buf = asn_encode_int(buf, length,
                             (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             pdu->err_stat);
        BAIL_OUT;

        buf = asn_encode_int(buf, length,
                             (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             pdu->err_ind);
        BAIL_OUT;

        return buf;
}
