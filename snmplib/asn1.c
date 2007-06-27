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
#include <snmp/asn1.h>
#include <snmp/snmp.h>

#ifndef SNMP_SET_ERRNO
# define SNMP_SET_ERRNO(e)
#endif

/* Obtain the length of a current object.
   Input:  data points to the start of object length
   Output: length contains object length.
   Return: pointer to the first byte of the object.  
   Error:  Returns NULL, does not change args */  
u_char *
asn_decode_length(u_char *data, u_int *length)
{
        u_char size = *data++;
        
        if (size & ASN_LONG_LEN) {
                u_int len;
                
                size &= ~ASN_LONG_LEN;  /* size contains the actual count
                                           of length bytes that follow */
                if (!size || size > sizeof(int)) {
                        SNMP_SET_ERRNO(E_ASN_DECODE);
                        return NULL;
                }
                
                len = 0;
                while (size--) {
                        len <<= 8;
                        len |= *data++;
                }
                *length = len;
        } else 
                *length = size;
        return data;
}

/* Encode object length.
   Input: data points to data space
          *datalength contains size of data space
   Output:*datalength contains number of bytes left in the data space
   Return:Pointer to the byte immediately past the encoded length
   Error: NULL */
u_char *
asn_encode_length(u_char *data, int *datalength, u_int length)
{
        if (*datalength < 1) {
                SNMP_SET_ERRNO(E_ASN_ENCODE);
                return NULL;
        }
        
        if (length < 0x80) {
                *data++ = (u_char) length;
        } else if (length < 0xff) {
                if (*datalength < 2) {
                        SNMP_SET_ERRNO(E_ASN_ENCODE);
                        return NULL;
                }

                *data++ = (u_char)(ASN_LONG_LEN|0x01);
                *data++ = (u_char)length;
        } else {
                /*length can be at most 0xffff */
                if (*datalength < 3) {
                        SNMP_SET_ERRNO(E_ASN_ENCODE);
                        return NULL;
                }
                
                *data++ = (u_char)(ASN_LONG_LEN|0x02);
                *data++ = (u_char)((length >> 8) & 0xff);
                *data++ = (u_char)(length & 0xff);
        }
        return data;
}

u_char *
asn_recode_length(u_char *data, u_int length)
{
        /*length can be at most 0xffff */
        *data++ = (u_char)(ASN_LONG_LEN|0x02);
        *data++ = (u_char)((length >> 8) & 0xff);
        *data++ = (u_char)(length & 0xff);
        return data;
}

/* Build an ASN header.
   Input: data points to data space;
          *datalength contains size of data space;
          type is the object type;
          length is object length.
   Output:*datalength contains number of bytes left in the data space
   Return:Pointer to the byte immediately past the header (i.e. start of
          data).
   Error: NULL */
u_char *
asn_encode_header(u_char *data, int *datalength, u_char type, int length)
{
        if (*datalength < 1) {
                SNMP_SET_ERRNO(E_ASN_ENCODE);
                return (NULL);
        }
        *data++ = type;
        --*datalength;
        return asn_encode_length(data, datalength, length);
}

u_char *
asn_decode_header(u_char *data, int *datalength, u_char *type)
{
        if (*datalength < 1) {
                SNMP_SET_ERRNO(E_ASN_DECODE);
                return (NULL);
        }
        *type = *data++;
        --*datalength;
        return asn_decode_length(data, datalength);
}

u_char *
asn_encode_null(u_char *data, int *datalength, u_char type)
{
        return asn_encode_header(data, datalength, type, 0);
}

/* Integer objects
   ASN.1 spec:
      integer ::= 0x02 asnlength byte {byte}*   */     

/* Decode an integer object.
   Input: data => dataspace;
          datalength => size of dataspace;
          intp - output buffer for integer value;
          intsize => size of output buffer.
   Output:datalength => number of bytes left in dataspace;
          type => asn type of object (alvays 0x02);
          intp => decoded integer value.
   Return:Pointer to the byte immediately past the decoded object.
   Error: NULL */
u_char *
asn_decode_int(u_char *data, int *datalength, u_char *type,
	       int *intp, int intsize)
{
        u_int count;
        u_char *buf = data;
        int value;
        
        if (intsize != sizeof(int)) {
                SNMP_SET_ERRNO(E_ASN_DECODE);
                return NULL;
        }
        *type = *buf++;
        buf = asn_decode_length(buf, &count);
        if (!buf)
                return buf;

        if (count + (buf - data) > *datalength) /* || count > intsize)*/ {
                SNMP_SET_ERRNO(E_ASN_DECODE);
                return NULL;
        }

        /* Initialize value */
        if (*buf & 0x80)
                value = -1;
        else
                value = 0;

        while (count--) {
                value <<= 8;
                value |= *buf++;
        }

        *datalength -= buf - data;
        *intp = value;
        return buf;
}

/* build an ASN object containig an integer
   Input: data => dataspace;
          datalength => size of dataspace;
          type - object type;
          intval integer value to be encoded;
   Output:datalength => number of bytes left in dataspace.
   Return:Pointer to the byte immediately past the encoded object.
   Error: NULL */
   
u_char *
asn_encode_int(u_char *data, int *datalength, u_char type, int intval)
{
        u_int mask;
        u_int intsize = sizeof(int);
        
        /*
         * Truncate "unnecessary" bytes off of the most significant end of this
         * 2's complement integer.  There should be no sequence of 9
         * consecutive 1's or 0's at the most significant end of the
         * integer.
         */
        mask = (u_int) 0x1FF << ((8 * (sizeof(int) - 1)) - 1);

        while ((((intval & mask) == 0) || ((intval & mask) == mask))
               && intsize > 1) {
                intsize--;
                intval <<= 8;
        }

        if (!(data = asn_encode_header(data, datalength, type, intsize)) ||
            *datalength < intsize) {
                SNMP_SET_ERRNO(E_ASN_ENCODE);
                return NULL;
        }

        *datalength -= intsize;
        mask = (u_int) 0xff << (8 * (sizeof(int) - 1));
        while (intsize--) {
                *data++ = (u_char) ((intval & mask) >> (8*(sizeof(int) - 1)));
                intval <<= 8;
        }
        
        return data;
}

/* String objects.
   ASN.1 spec:
       octet string ::= primstring | cmpdstring
       primstring ::= 0x04 asnlength byte {byte}*
       cmpdstring ::= 0x24 asnlength string {string}* */

/* Decode a string object.
   Input: data => dataspace;
          datalength => size of dataspace;
          string - output buffer for octet string;
          strlength => size of output buffer.
   Output:datalength => number of bytes left in dataspace;
          type => asn type of object;
          string => decoded octet string;
          strlength => number of bytes actually used in string.
   Return:Pointer to the byte immediately past the decoded object.
   Error: NULL */
u_char *
asn_decode_string(u_char *data, int *datalength, u_char *type,
		  u_char *string, int *strlength)
{
        u_char *buf = data;
        u_int count;
        
        *type = *buf++;
        if ((buf = asn_decode_length(buf, &count)) == NULL ||
            count + (buf - data) > *datalength ||
            count > *strlength) {
                SNMP_SET_ERRNO(E_ASN_DECODE);
                return NULL;
        }

        *strlength = count;
        while (count--)
                *string++ = *buf++;
        *datalength -= buf - data;
        return buf;
}

/* build an ASN object containig a string.
   Input: data => dataspace;
          datalength => size of dataspace;
          type - object type;
          string - conents of the string object;
          strlength - number of bytes in string
   Output:datalength => number of bytes left in dataspace.
   Return:Pointer to the byte immediately past the encoded object.
   Error: NULL */
u_char *
asn_encode_string(u_char *data, int *datalength, u_char type,
		  u_char *string, int strlength)
{
        data = asn_encode_header(data, datalength, type, strlength);
        if (!data || *datalength < strlength) {
                SNMP_SET_ERRNO(E_ASN_ENCODE);
                return NULL;
        }
        *datalength -= strlength;
        while (strlength--)
                *data++ = *string++;
        return data;
}

/* Object Identifiers
   ASN.1 spec
      objid ::= 0x06 asnlength subidentifier {subidentifier}*
      subidentifier ::= {leadingbyte}* lastbyte
      leadingbyte ::= 1 7bitvalue
      lastbyte ::= 0 7bitvalue */

#define BOGUS_40

/* Decode an oid object.
   Input: data => dataspace;
          datalength => size of dataspace;
          type => object type;
          obid => oid output buffer.
          obidlength => size of output buffer.
   Output:datalength => number of bytes left in dataspace;
          type => asn type of object;
          obid => decoded oid;
          obidlength => real oid length.
   Return:Pointer to the byte immediately past the decoded object.
   Error: NULL */
u_char *
asn_decode_oid(u_char *data, int *datalength, u_char *type,
	       oid_t obid, int *obidlength)
{
        u_char *buf = data;
        u_int count;
        u_int subid;
        oid_t oidp = obid + 1;
        
        *type = *buf++;
        buf = asn_decode_length(buf, &count);
        if (!buf || count + (buf - data) > *datalength) {
                SNMP_SET_ERRNO(E_ASN_DECODE);
                return NULL;
        }

        if (count == 0) 
                obid[0] = obid[1] = 0;
        
        --*obidlength;
        while (count > 0 && (*obidlength)-- > 0) {

                /* {leadingbyte}* */
                subid = 0;
                do {
                        subid = (subid<<7)+(*buf & ~ASN_BIT8);
                        count--;
                } while (*buf++ & ASN_BIT8);

                if (subid > MAX_SUBID) {
                        SNMP_SET_ERRNO(E_ASN_DECODE);
                        return NULL;
                }
                *oidp++ = (subid_t) subid;
        }
#ifdef BOGUS_40
        /* The first subid is actually oid[0]*40+oid[1].
           I don't know why. */ 
        subid = (u_int)obid[1];
        obid[1] = (u_char) (subid % 40);
        obid[0] = (u_char) ((subid-obid[1])/40);
#endif
        *obidlength = (int) (oidp - obid);
        *datalength -= (buf-data);
        return buf;
}
                
/* build an ASN object containig an oid.
   Input: data => dataspace;
          datalength => size of dataspace;
          type - object type;
          obid - oid value;
          obidlength - length of obid.
   Output:datalength => number of bytes left in dataspace.
   Return:Pointer to the byte immediately past the encoded object.
   Error: NULL */
u_char *
asn_encode_oid(u_char *data, int *datalength, u_char type,
	       oid_t obid, int obidlength)
{
        int length;
        u_char *buf, *bp;
        u_int subid;
        
#define CHKLEN() if (length-- < 1) goto err;

        length = *datalength;
        buf = asn_encode_header(data, &length, type, 0xffff);
        if (!buf) {
err:
                SNMP_SET_ERRNO(E_ASN_ENCODE);
                return NULL;
        }
        
        bp = buf;
#ifdef BOGUS_40
        if (obidlength < 2) {
                *bp++ = 0;
                obidlength = 0;
        } else {
                *bp++ = obid[1] + (obid[0] * 40);
                obidlength -= 2;
                obid += 2;
        }
#endif  
        while (obidlength--) {
                subid = *obid++;
                if (subid < 0x7f) { /* lastbyte */
                        CHKLEN();
                        *bp++ = subid;
                } else { /* leadingbyte */
                        register u_char *p, *q, tb;
                        
                        p = bp;
                        for (; subid > 0x7f; subid >>= 7) {
                                CHKLEN();
                                *bp++ = (u_char)((subid & 0x7f)|ASN_BIT8);
                        }
                        
                        /* add lastbyte */
                        CHKLEN();
                        *bp++ = (u_char) subid | ASN_BIT8;
                        
                        /* swap bytes */
                        for (q = bp-1; q > p; q--, p++) {
                                tb = *q;
                                *q = *p;
                                *p = tb;
                        }
                        /* make lastbyte 7-bit */
                        bp[-1] &= ~ASN_BIT8;
                }
        }

        asn_recode_length(data+1, bp - buf);
        *datalength = length;
        return bp;
}

