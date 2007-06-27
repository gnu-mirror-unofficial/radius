/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001, 2007 Free Software Foundation, Inc.
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

#include <sys/types.h>
#include <sys/time.h>

typedef u_int subid_t;
typedef subid_t *oid_t;
#define MAX_SUBID   0xffffffff   /* should be UINT_MAX? */
#define MAX_OID_LEN         128 /* max number of subids in an oid */

#define OIDLEN(oid) (oid)[0]
#define OIDSIZE(oid) sizeof((oid)[0])*OIDLEN(oid)
#define OIDPTR(oid) ((oid)+1)
#define SUBID(oid,n) OIDPTR(oid)[n]

#define ASN_BOOLEAN         (0x01)
#define ASN_INTEGER         (0x02)
#define ASN_BIT_STR         (0x03)
#define ASN_OCTET_STR       (0x04)
#define ASN_NULL            (0x05)
#define ASN_OBJECT_ID       (0x06)
#define ASN_SEQUENCE        (0x10)
#define ASN_SET             (0x11)

#define ASN_UNIVERSAL       (0x00)
#define ASN_APPLICATION     (0x40)
#define ASN_CONTEXT         (0x80)
#define ASN_PRIVATE         (0xC0)

#define ASN_PRIMITIVE       (0x00)
#define ASN_CONSTRUCTOR     (0x20)

#define ASN_LONG_LEN        (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8            (0x80)

#define ASN_IPADDRESS       (ASN_APPLICATION | 0)
#define ASN_COUNTER         (ASN_APPLICATION | 1)
#define ASN_GAUGE           (ASN_APPLICATION | 2)
#define ASN_UNSIGNED        ASN_GAUGE
#define ASN_TIMETICKS       (ASN_APPLICATION | 3)
#define ASN_OPAQUE          (ASN_APPLICATION | 4)  
#define ASN_COUNTER64       (ASN_APPLICATION | 6)
#define ASN_FLOAT           (ASN_APPLICATION | 8)
#define ASN_DOUBLE          (ASN_APPLICATION | 9)
#define ASN_INTEGER64       (ASN_APPLICATION | 10)
#define ASN_UNSIGNED64      (ASN_APPLICATION | 11)

u_char *asn_decode_length(u_char *data, u_int *length);
u_char *asn_encode_length(u_char *data, int *datalength, u_int length);
u_char *asn_recode_length(u_char *data, u_int length);
u_char *asn_decode_header(u_char *data, int *datalength, u_char *type);
u_char *asn_encode_header(u_char *data, int *datalength,
                          u_char type, int length);
u_char *asn_encode_null(u_char *data, int *datalength, u_char type);
u_char *asn_decode_int(u_char *data, int *datalength,
                       u_char *type, int *intp, int intsize);
u_char *asn_encode_int(u_char *data, int *datalength,
                       u_char type, int intval);

#define asn_decode_uint(data, datalength, type, intp, intsize) \
 asn_decode_int(data, datalength, type, intp, intsize)
#define asn_encode_uint(data, datalength, type, intval) \
 asn_encode_int(data, datalength, type, intval)

u_char *asn_decode_string(u_char *data, int *datalength,
                          u_char *type, u_char *string, int *strlen);
u_char *asn_encode_string(u_char *data, int *datalength,
                          u_char type, u_char *string, int strlen);
u_char *asn_decode_oid(u_char *data, int *datalength, 
                       u_char *type, oid_t obid, int *obidlength);
u_char *asn_encode_oid(u_char *data, int *datalength,
                       u_char type, oid_t obid, int obidlength);

char *sprint_oid(char *buf, int buflen, oid_t name);

