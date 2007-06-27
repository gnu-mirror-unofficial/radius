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
#include <stdio.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>

oid_t
oid_dup(oid_t oid)
{
        oid_t new_oid;

        new_oid = snmp_alloc(OIDSIZE(oid)+sizeof(oid[0]));
        if (!new_oid)
                return NULL;
        memcpy(new_oid, oid, OIDSIZE(oid)+sizeof(oid[0]));
        return new_oid;
}

oid_t
oid_create(int len)
{
        oid_t oid;

        if ((oid = snmp_alloc((len+1)*sizeof(oid[0])))) 
                OIDLEN(oid) = len;
        return oid;
}

oid_t 
oid_create_from_string(char *str)
{
        char *tok;
        int len;
        oid_t name, p;

        if (*str == '.')
                str++;
        
        for (tok = str, len = 0; *tok; tok++)
                if (*tok == '.')
                        len++;
        len++;
        name = snmp_alloc(sizeof(*name) * (len+1));
        if (!name) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                return NULL;
        }
        OIDLEN(name) = len;
        p = OIDPTR(name);
        tok = str;
        for (;;) {
                *p++ = strtol(tok, &tok, 10);
                if (*tok == 0)
                        break;
                if (*tok++ != '.') {
                        SNMP_SET_ERRNO(E_SNMP_BAD_OID);
                        snmp_free(name);
                        name = NULL;
                        break;
                }
        } 
        return name;
}

oid_t
oid_create_from_subid(int len, subid_t *subid)
{
        oid_t oid;

        oid = snmp_alloc((len+1)*sizeof(oid[0]));
        if (!oid) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                return NULL;
        }
        OIDLEN(oid) = len;
        memcpy(OIDPTR(oid), subid, len*sizeof(oid[0]));
        return oid;
}

int
oid_cmp(oid_t a, oid_t b)
{
        int i;
        
        if (OIDLEN(a) != OIDLEN(b))
                return 1;
        for (i = 0; i < OIDLEN(a); i++)
                if (SUBID(a,i) != SUBID(b,i))
                        return 1;
        return 0;
}

char *
sprint_oid(char *buf, int buflen, oid_t oid)
{
        int i, d;
        char *p, *start;
        char temp[64];
        int len = OIDLEN(oid);
        oid_t name = OIDPTR(oid);

        start = buf;
        for (i = 0; i < len; i++) {
                if (buflen < 3) {
                        *buf++ = '>';
                        break;
                }

                sprintf(temp, "%d", *name);
                d = strlen(temp) + 1;
                if (buflen - d < 3) {
                        *buf++ = '>';
                        break;
                }
                buflen -= d;
                *buf++ = '.';
                for (p = temp; *p; )
                     *buf++ = *p++;
                name++;
        }
        *buf = 0;
        return start;
}
