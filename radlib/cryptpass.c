/* This file is part of GNU RADIUS.
   Copyright (C) 2000, 2001 Sergey Poznyakoff
  
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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <radius.h>
#include <mem.h>

/* From rfc2138:
      Call the shared secret S and the pseudo-random 128-bit Request
      Authenticator RA.  Break the password into 16-octet chunks p1, p2,
      etc.  with the last one padded at the end with nulls to a 16-octet
      boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
      intermediate values b1, b2, etc.

         b1 = MD5(S + RA)       c(1) = p1 xor b1
         b2 = MD5(S + c(1))     c(2) = p2 xor b2
                .                       .
                .                       .
                .                       .
         bi = MD5(S + c(i-1))   c(i) = pi xor bi

      The String will contain c(1)+c(2)+...+c(i) where + denotes
      concatenation. */

void
encrypt_password(pair, password, vector, secret)
	VALUE_PAIR *pair;
	char *password; /* Cleantext password */
	char *vector;   /* Request authenticator */
	char *secret;   /* Shared secret */
{
	int passlen;
	int secretlen;
	int nchunks;
	int buflen;
	char *passbuf;
	int md5len;
	char *md5buf;
	char digest[AUTH_VECTOR_LEN];
	char *cp;
	int i, j;
	
	passlen = strlen(password);
	nchunks = (passlen + AUTH_VECTOR_LEN - 1) / AUTH_VECTOR_LEN;
	buflen = nchunks * AUTH_VECTOR_LEN;

	pair->strvalue = alloc_string(buflen);
	pair->strlength = buflen;
	passbuf = pair->strvalue;

	/* Prepare passbuf */
	memset(passbuf, 0, buflen);
	memcpy(passbuf, password, passlen);

	secretlen = strlen(secret);
	md5len = secretlen + AUTH_VECTOR_LEN;
	md5buf = emalloc(md5len);
	memcpy(md5buf, secret, secretlen);

	cp = vector;
	for (i = 0; i < buflen; ) {
		/* Compute next MD5 hash */
		memcpy(md5buf + secretlen, cp, AUTH_VECTOR_LEN);
		md5_calc(digest, md5buf, md5len);
		/* Save hash start */
		cp = passbuf + i;
		/* Encrypt next chunk */
		for (j = 0; j < AUTH_VECTOR_LEN; j++, i++)
			passbuf[i] ^= digest[j];
	}
	efree(md5buf);
}

void
decrypt_password(password, pair, vector, secret)
	char *password;   /* At least AUTH_STRING_LEN+1 characters long */
	VALUE_PAIR *pair; /* Password pair */
	char *vector;     /* Request authenticator */
	char *secret;     /* Shared secret */
{
	int md5len;
	char *md5buf;
	char digest[AUTH_VECTOR_LEN];
	char *cp;
	int secretlen;
	int passlen;
	int i, j;
	
	/* Initialize password buffer */
	/* FIXME: control length */
	memcpy(password, pair->strvalue, pair->strlength);
	passlen = pair->strlength;
	
	/* Prepare md5buf */
	secretlen = strlen(secret);
	md5len = secretlen + AUTH_VECTOR_LEN;
	md5buf = emalloc(md5len);
	memcpy(md5buf, secret, secretlen);

	cp = vector;
	for (i = 0; i < passlen; ) {
		/* Compute next MD5 hash */
		memcpy(md5buf + secretlen, cp, AUTH_VECTOR_LEN);
		md5_calc(digest, md5buf, md5len);
		/* Save hash start */
		cp = pair->strvalue + i;
		/* Decrypt next chunk */
		for (j = 0; j < AUTH_VECTOR_LEN; j++, i++)
			password[i] ^= digest[j];
	}
	password[passlen+1] = 0;
	efree(md5buf);
}
