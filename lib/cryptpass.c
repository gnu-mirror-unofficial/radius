/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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

#include <stdio.h>
#include <stdlib.h>

#include <radlib.h>

/* From rfc 2138:
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
      concatenation.


   From rfc 2868:
         Call the shared secret S, the pseudo-random 128-bit Request
         Authenticator (from the corresponding Access-Request packet) R,
         and the contents of the Salt field A.  Break P into 16 octet
         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
         Intermediate values b(1), b(2)...c(i) are required.  Encryption
         is performed in the following manner ('+' indicates
         concatenation):

            b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
            b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
                        .                      .
                        .                      .
                        .                      .
            b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

         The resulting encrypted String field will contain
         c(1)+c(2)+...+c(i).

 The rfc2138 algorithm can be obtained from rfc2868 by setting salt
 length to zero */

/* General purpose encryption and decryption functions. These satisfy
   both rfc 2138 and 2868. */
void
grad_encrypt_text(u_char **encr_text,
		  size_t *encr_size,
		  u_char *password,   /* Cleantext password */
		  u_char *authenticator,     /* Request authenticator */
		  u_char *secret,     /* Shared secret */
		  u_char *salt,
		  size_t saltlen)
{
        int passlen;
        int secretlen;
        int nchunks;
        int buflen;
        u_char *passbuf;
        int md5len;
        u_char *md5buf;
        u_char digest[GRAD_AUTHENTICATOR_LENGTH];
        u_char *cp;
        int i, j;
        
        passlen = strlen(password);
        nchunks = (passlen + GRAD_AUTHENTICATOR_LENGTH - 1) / GRAD_AUTHENTICATOR_LENGTH;
        buflen = nchunks * GRAD_AUTHENTICATOR_LENGTH;

        *encr_text = grad_emalloc(buflen);
        *encr_size = buflen;
        passbuf = *encr_text;

        /* Prepare passbuf */
        memset(passbuf, 0, buflen);
        memcpy(passbuf, password, passlen);

        secretlen = strlen(secret);
        md5len = secretlen + GRAD_AUTHENTICATOR_LENGTH;
        md5buf = grad_emalloc(md5len + saltlen);
        memcpy(md5buf, secret, secretlen);

        cp = authenticator;
        for (i = 0; i < buflen; ) {
                /* Compute next MD5 hash */
                memcpy(md5buf + secretlen, cp, GRAD_AUTHENTICATOR_LENGTH);
		if (i == 0 && saltlen) {
			memcpy(md5buf + md5len, salt, saltlen);
			grad_md5_calc(digest, md5buf, md5len + saltlen);
		} else
			grad_md5_calc(digest, md5buf, md5len);
                /* Save hash start */
                cp = passbuf + i;
                /* Encrypt next chunk */
                for (j = 0; j < GRAD_AUTHENTICATOR_LENGTH; j++, i++)
                        passbuf[i] ^= digest[j];
        }
        grad_free(md5buf);
}

void
grad_decrypt_text(u_char *password,   /* At least GRAD_STRING_LENGTH+1
					 characters long */
		  u_char *encr_text,  /* encrypted text */
		  size_t encr_size,   /* Size of encr_text and password
					 buffers */
		  u_char *authenticator,     /* Request authenticator */
		  u_char *secret,     /* Shared secret */
		  u_char *salt,
		  size_t saltsize)
{
        int md5len;
        u_char *md5buf;
        u_char digest[GRAD_AUTHENTICATOR_LENGTH];
        u_char *cp;
        int secretlen;
        int i, j;
        
        /* Initialize password buffer */
        memcpy(password, encr_text, encr_size);
        
        /* Prepare md5buf */
        secretlen = strlen(secret);
        md5len = secretlen + GRAD_AUTHENTICATOR_LENGTH;
        md5buf = grad_emalloc(md5len);
        memcpy(md5buf, secret, secretlen);

        cp = authenticator;
        for (i = 0; i < encr_size; ) {
                /* Compute next MD5 hash */
                memcpy(md5buf + secretlen, cp, GRAD_AUTHENTICATOR_LENGTH);
		if (i == 0 && saltsize) {
			memcpy(md5buf + md5len, salt, saltsize);
			grad_md5_calc(digest, md5buf, md5len + saltsize);
		} else
			grad_md5_calc(digest, md5buf, md5len);
                /* Save hash start */
                cp = encr_text + i;
                /* Decrypt next chunk */
                for (j = 0; j < GRAD_AUTHENTICATOR_LENGTH; j++, i++)
                        password[i] ^= digest[j];
        }
        password[encr_size] = 0;
        grad_free(md5buf);
}


/* RFC 2138 functions */
void
grad_encrypt_password(grad_avp_t *pair,
		      char *password, /* Cleantext password */
		      char *authenticator,   /* Request authenticator */
		      char *secret)   /* Shared secret */
{
	u_char *encr_text;
	size_t encr_size;
	
	grad_encrypt_text(&encr_text, &encr_size,
			  password, authenticator, secret, 
			  NULL, 0);
        pair->avp_strvalue = encr_text;
        pair->avp_strlength = encr_size;
}

void
grad_decrypt_password(char *password,   /* At least GRAD_STRING_LENGTH+1
					   characters long */
		      grad_avp_t *pair, /* Password pair */
		      char *authenticator,     /* Request authenticator */
		      char *secret)     /* Shared secret */
{
	grad_decrypt_text(password,
			  pair->avp_strvalue,
			  pair->avp_strlength,
			  authenticator,
			  secret, 
			  NULL,
		     0);
}

/* Special case:
   Decrypt a password encrypted using broken algorythm.
   This is for use with such brain-damaged NASes as MAX ascend. */
void
grad_decrypt_password_broken(char *password, /* At least GRAD_STRING_LENGTH+1
						characters long */
			     grad_avp_t *pair, /* Password pair */
			     char *authenticator,     /* Request authenticator */
			     char *secret)     /* Shared secret */
{
        int md5len;
        char *md5buf;
        char digest[GRAD_AUTHENTICATOR_LENGTH];
        int secretlen;
        int passlen;
        int i, j;
        
        /* Initialize password buffer */
        /* FIXME: control length */
        memcpy(password, pair->avp_strvalue, pair->avp_strlength);
        passlen = pair->avp_strlength;
        
        /* Prepare md5buf */
        secretlen = strlen(secret);
        md5len = secretlen + GRAD_AUTHENTICATOR_LENGTH;
        md5buf = grad_emalloc(md5len);
        memcpy(md5buf, secret, secretlen);

        /* Compute next MD5 hash */
        memcpy(md5buf + secretlen, authenticator, GRAD_AUTHENTICATOR_LENGTH);
        grad_md5_calc(digest, md5buf, md5len);

        for (i = 0; i < passlen; ) {
                /* Decrypt next chunk */
                for (j = 0; j < GRAD_AUTHENTICATOR_LENGTH; j++, i++)
                        password[i] ^= digest[j];
        }
        grad_free(md5buf);
}
	

/* RFC 2868 */
      
void
grad_encrypt_tunnel_password(grad_avp_t *pair,
			     u_char tag,
			     char *password, /* Cleantext password */
			     char *authenticator,   /* Request authenticator */
			     char *secret)   /* Shared secret */
{
	u_char *encr_text;
	size_t encr_size;
	char *plaintext;
	size_t length = strlen(password);
	unsigned short salt = htons( (((long)pair ^ *(long *)authenticator) & 0xffff)
				     | 0x8000 );
	
	plaintext = grad_emalloc(length+2);
	plaintext[0] = length;
	memcpy(&plaintext[1], password, length + 1);
	grad_encrypt_text(&encr_text, &encr_size,
			  plaintext, authenticator, secret, 
			  (u_char*) &salt, 2);
	grad_free(plaintext);
	
	pair->avp_strlength = 3 + encr_size;
	pair->avp_strvalue = grad_emalloc(pair->avp_strlength);
	pair->avp_strvalue[0] = tag;
	memcpy(&pair->avp_strvalue[1], &salt, 2);
	memcpy(&pair->avp_strvalue[3], encr_text, encr_size);
	grad_free(encr_text);
}

void
grad_decrypt_tunnel_password(char *password,   /* At least GRAD_STRING_LENGTH+1
						  characters long */
			     u_char *tag,
			     grad_avp_t *pair, /* Password pair */
			     char *authenticator,     /* Request authenticator */
			     char *secret)     /* Shared secret */
{
	size_t length;
	grad_decrypt_text(password,
			  pair->avp_strvalue + 3,
			  pair->avp_strlength - 3,
			  authenticator,
			  secret, 
			  &pair->avp_strvalue[1],
			  2);
	length = *(u_char*) password;
	memmove(password, password + 1, length);
	password[length] = 0;
	*tag = pair->avp_strvalue[0];
}
