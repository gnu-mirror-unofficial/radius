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

/* free a *single* snmp variable */
void
snmp_var_free(struct snmp_var *var)
{
        if (!var)
                return;
        switch (var->type) {
        case ASN_BOOLEAN:
        case ASN_INTEGER:
        case ASN_NULL:
        case SMI_COUNTER32:
        case SMI_GAUGE32:
        case SMI_TIMETICKS:
                break;
        case ASN_OCTET_STR:
        case SMI_IPADDRESS:
        case SMI_OPAQUE:
        case ASN_BIT_STR:
                snmp_free(var->var_str);
                break;
        case ASN_OBJECT_ID:
                snmp_free(var->var_oid);
                break;
        default:
                abort();
        }
        snmp_free(var->name);
        snmp_free(var);
}

/* free whole snmp variable list */
void
snmp_var_free_list(struct snmp_var *var)
{
        struct snmp_var *next;

        while (var) {
                next = var->next;
                snmp_var_free(var);
                var = next;
        }
}

struct snmp_var *
snmp_var_create(oid_t oid)
{
        struct snmp_var *var;

        var = snmp_alloc(sizeof(*var));
        if (!var) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                return NULL;
        }
        
        var->name = oid_dup(oid);
        if (!var->name) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                snmp_free(var);
                return NULL;
        }
        var->type = ASN_NULL;
        var->next = NULL;
        return var;
}

struct snmp_var *
snmp_var_dup(struct snmp_var *src)
{
        struct snmp_var *var;

        if ((var = snmp_var_create(src->name)) == NULL)
                return NULL;
        var->type = src->type;
        var->val_length = src->val_length;
        switch (var->type) {
        case ASN_BOOLEAN:
        case ASN_INTEGER:
        case ASN_NULL:
        case SMI_COUNTER32:
        case SMI_GAUGE32:
        case SMI_TIMETICKS:
                var->var_int = src->var_int;
                break;
        case ASN_OCTET_STR:
        case SMI_IPADDRESS:
        case SMI_OPAQUE:
        case ASN_BIT_STR:
                var->var_str = snmp_alloc(src->val_length);
                if (!var->var_str) {
                        SNMP_SET_ERRNO(E_SNMP_NOMEM);
                        snmp_free(var);
                        return NULL;
                }
                memcpy(var->var_str, src->var_str, src->val_length);
                break;
        case ASN_OBJECT_ID:
                var->var_oid = oid_dup(src->var_oid);
                if (!var->var_oid) {
                        SNMP_SET_ERRNO(E_SNMP_NOMEM);
                        snmp_free(var);
                        return NULL;
                }
                break;
        default:
                abort();
        }
        return var;
}

struct snmp_var *
snmp_var_dup_list(struct snmp_var *var)
{
        struct snmp_var *var_head, *var_tail, *vp;

        var_head = var_tail = NULL;
        for (; var; var = var->next) {
                if ((vp = snmp_var_dup(var)) == NULL) {
                        snmp_var_free_list(var_head);
                        return NULL;
                }
                if (var_tail)
                        var_tail->next = vp;
                else
                        var_head = vp;
                var_tail = vp;
        }
        return var_head;
}
        
/* RFC 1905: Protocol Operations for SNMPv2
   VarBind ::= SEQUENCE {
         name ObjectName
         CHOICE {
                 value ObjectSyntax
                 unSpecified NULL
                 noSuchObject[0] NULL
                 noSuchInstance[1] NULL
                 endOfMibView[2] NULL
         }
   }
*/

u_char *
snmp_var_decode(u_char *data, int *length, struct snmp_var **var_head,
		int version)
{
        u_char *buf, *tmp;
        u_char *data_ptr;
        u_char type;
        int list_length = *length;
        int var_length, data_len;
        subid_t oid[MAX_OID_LEN+1];
        struct snmp_var *var = NULL, *var_tail;
        
        /* Determine length of the variable list */
        buf = asn_decode_header(data, &list_length, &type);
        if (!buf)
                return NULL;
        if (type != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
                SNMP_SET_ERRNO(E_SNMP_DECODE);
                return NULL;
        }

        *var_head = var_tail = NULL;
        /* Parse variable list */
        while (list_length > 0) {

                /* determine length of this variable; */
                var_length = list_length;
                tmp = asn_decode_header(buf, &var_length, &type);
                if (!tmp)
                        goto err;

                /* adjust total length and restore buffer pointer */
                list_length -= var_length + (tmp - buf);
                buf = tmp;

                if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
                        SNMP_SET_ERRNO(E_SNMP_DECODE);
                        goto err;
                }

                /* read oid */
                OIDLEN(oid) = MAX_OID_LEN;
                buf = asn_decode_oid(buf, &var_length, &type,
                                     OIDPTR(oid), &OIDLEN(oid));
                if (!buf)
                        goto err;

                if (type != (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID)) {
                        SNMP_SET_ERRNO(E_SNMP_DECODE);
                        goto err;
                }

                /* allocate variable */
                var = snmp_var_create(oid);

                /* Preserve pointer to the start of data */
                data_ptr = buf;
                data_len = var_length;

                /* read object's header */
                buf = asn_decode_header(buf, &data_len, &var->type);
                if (!buf) 
                        goto err;

                /* now depending on type ... */
                switch (var->type) {
                case ASN_INTEGER:
                        var->val_length = sizeof(var->var_int);
                        buf = asn_decode_int(data_ptr, &var_length,
                                             &var->type, &var->var_int,
                                             var->val_length);
                        break;

                case SMI_COUNTER32:
                case SMI_GAUGE32:
                case SMI_TIMETICKS:
                        var->val_length = sizeof(var->var_int);
                        buf = asn_decode_uint(data_ptr, &var_length,
                                              &var->type, &var->var_int,
                                              var->val_length);
                        break;

                case ASN_OCTET_STR:
                case SMI_IPADDRESS:
                case SMI_OPAQUE:
                        var->val_length = var_length; /* at most ... */
                        var->var_str = snmp_alloc(var->val_length);
                        if (!var->var_str) {
                                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                                goto err;
                        }
                        buf = asn_decode_string(data_ptr, &var_length,
                                                &var->type, var->var_str,
                                                &var->val_length);
                        break;

                case ASN_OBJECT_ID:
                        var->val_length = MAX_OID_LEN;
                        buf = asn_decode_oid(data_ptr, &var_length,
                                             &var->type, OIDPTR(oid),
                                             &var->val_length);
                        if (buf) {
                                OIDLEN(oid) = var->val_length;
                                var->var_oid = oid_dup(oid);
                        }
                        break;

                case ASN_NULL:
                        break;

                default:
                        SNMP_SET_ERRNO(E_SNMP_BAD_VARTYPE);
                        break;
                }

                if (!buf)
                        goto err;

                if (!var_tail)
                        *var_head = var;
                else
                        var_tail->next = var;
                var_tail = var;
                var = NULL;
        }

        return buf;
        
err:
        snmp_var_free(var);
        snmp_var_free_list(*var_head);
        return NULL;
}

u_char *
snmp_var_encode(u_char *data, int *length, struct snmp_var *var, int version)
{
        u_char *buf = data;
        u_char *header_ptr, *header_end;
        
        for (; var; var = var->next) {
                header_ptr = buf;
                buf = asn_encode_header(buf, length,
                                        (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                        0xffff);
                if (!buf)
                        return NULL;

                header_end = buf;

                buf = asn_encode_oid(buf, length,
                                     (ASN_UNIVERSAL |
                                      ASN_PRIMITIVE |
                                      ASN_OBJECT_ID),
                                     OIDPTR(var->name), OIDLEN(var->name));
                if (!buf)
                        return NULL;

                switch (var->type) {
                case ASN_INTEGER:
                        buf = asn_encode_int(buf, length, var->type,
                                             var->var_int);
                        break;
                case SMI_COUNTER32:
                case SMI_GAUGE32: 
                case SMI_TIMETICKS:
                        buf = asn_encode_uint(buf, length, var->type,
                                              var->var_int);
                        break;
                case ASN_OCTET_STR:
                case SMI_IPADDRESS:
                case SMI_OPAQUE:
                        buf = asn_encode_string(buf, length, var->type,
                                                var->var_str, var->val_length);
                        break;

                case ASN_OBJECT_ID:
                        buf = asn_encode_oid(buf, length, var->type,
                                             OIDPTR(var->var_oid),
                                             OIDLEN(var->var_oid));
                        break;

                case ASN_NULL:
                        buf = asn_encode_null(buf, length, var->type);
                        break;

                default:
                        SNMP_SET_ERRNO(E_SNMP_NOT_SUPPORTED);
                        buf = NULL;
                }

                if (!buf)
                        return NULL;

                asn_recode_length(header_ptr+1,
                                  buf - header_end);
        }
        
        return buf;
}
