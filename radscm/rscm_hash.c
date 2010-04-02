/* This file is part of GNU Radius.
   Copyright (C) 2004, 2007, 2010 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sysdep.h>
#include <libguile.h>
#include <radius/radius.h>
#include <radius/radscm.h>
#include <radius/md4.h>
#include <radius/md5.h>
#include <radius/sha1.h>

SCM_DEFINE(rscm_md5_calc, "md5-calc", 1, 0, 0,
           (SCM INPUT),
	   "Compute MD5 hash of @var{input}")
#define FUNC_NAME s_rscm_md5_calc
{
	char digest[GRAD_AUTHENTICATOR_LENGTH];
	char *str;
	
	SCM_ASSERT (scm_is_string(INPUT), INPUT, SCM_ARG1, FUNC_NAME);
	str = scm_to_locale_string(INPUT);
	grad_md5_calc(digest, str, strlen(str));
	free(str);
	return scm_from_locale_stringn(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_md4_calc, "md4-calc", 1, 0, 0,
           (SCM INPUT),
	   ""Compute MD4 hash of @var{input}"")
#define FUNC_NAME s_rscm_md4_calc
{
	char digest[16];
	char *str;
	
	SCM_ASSERT(scm_is_string(INPUT), INPUT, SCM_ARG1, FUNC_NAME);
	str = scm_to_locale_string(INPUT);
	grad_md4_calc(digest, str, strlen(str));
	free(str);
	return scm_from_locale_stringn(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_sha1_calc_list, "sha1-calc-list", 1, 0, 0,
           (SCM HLIST),
	   "Compute SHA1 hash of strings from @var{hlist}")
#define FUNC_NAME s_rscm_sha1_calc_list
{
	unsigned char *input;
	size_t length;
	char digest[20];
	SHA1_CTX ctx;
	
	SCM_ASSERT(scm_is_pair(HLIST), HLIST, SCM_ARG1, FUNC_NAME);
	SHA1Init(&ctx);
	for(; !scm_is_null(HLIST); HLIST = SCM_CDR(HLIST)) {
		SCM car = SCM_CAR(HLIST);
		char *str;
		
		SCM_ASSERT(scm_is_string(car), car, SCM_ARG1, FUNC_NAME);
		str = scm_to_locale_string(car);
		SHA1Update(&ctx, str, strlen(str));
		free(str);
	}
	SHA1Final(digest, &ctx);
	return scm_from_locale_stringn(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_lm_password_hash, "lm-password-hash", 1, 0, 0,
           (SCM INPUT),
	   "Create an \"LM-password\" hash from the given @var{input}.")
#define FUNC_NAME s_rscm_lm_password_hash
{
	unsigned char digest[72];
	char *str;
	
	SCM_ASSERT(scm_is_string(INPUT), INPUT, SCM_ARG1, FUNC_NAME);
	str = scm_to_locale_string(INPUT);
	grad_lmpwdhash(str, digest);
	free(str);
	return scm_from_locale_stringn(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_mschap_response, "mschap-response", 2, 0, 0,
           (SCM PASSWORD, SCM CHALLENGE),
	   "FIXME")
#define FUNC_NAME s_rscm_mschap_response
{
	unsigned char digest[24];
	char *pass, *chlg;
	
	SCM_ASSERT(scm_is_string(PASSWORD), PASSWORD, SCM_ARG1, FUNC_NAME);
	SCM_ASSERT(scm_is_string(CHALLENGE), CHALLENGE, SCM_ARG2, FUNC_NAME);
	pass = scm_to_locale_string(PASSWORD);
	chlg = scm_to_locale_string(CHALLENGE);
	grad_mschap(pass, chlg, digest);
	free(pass);
	free(chlg);
	return scm_from_locale_stringn(digest, sizeof digest);
}
#undef FUNC_NAME

static const char *xlet = "0123456789ABCDEF";

SCM_DEFINE(rscm_string_hex_to_bin, "string-hex->bin", 1, 0, 0,
           (SCM STR),
	   "Convert @var{str} from hex to binary representation.")
#define FUNC_NAME s_rscm_string_hex_to_bin
{
	int i, len;
	unsigned char *p; 
	char *q;
	SCM ret;

	SCM_ASSERT(scm_is_string(STR), STR, SCM_ARG1, FUNC_NAME);
	len = scm_c_string_length(STR);
	if (len % 2)
		scm_misc_error(FUNC_NAME,
			       "Input string has odd length",
			       SCM_EOL);
	len /= 2;
	ret = scm_i_make_string(len, &q);
	p = scm_to_locale_string(STR);
	for (i = 0; i < len; i++) {
		char *c1, *c2;
		if (!(c1 = memchr(xlet, toupper(p[i << 1]), sizeof xlet))
		    || !(c2 = memchr(xlet, toupper(p[(i << 1) + 1]),
				     sizeof xlet))) 
			scm_misc_error(FUNC_NAME,
				       "Malformed input string",
				       SCM_EOL);
		q[i] = ((c1 - xlet) << 4) + (c2 - xlet);
	}
	free(p);
	return ret;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_string_bin_to_hex, "string-bin->hex", 1, 0, 0,
           (SCM STR),
	   "Convert @var{str} from binary to hex representation.")
#define FUNC_NAME s_rscm_string_bin_to_hex
{
	int i, len;
	unsigned char *p;
	char *q;
	SCM ret;

	SCM_ASSERT(scm_is_string(STR), STR, SCM_ARG1, FUNC_NAME);
	len = scm_c_string_length(STR);
	ret = scm_i_make_string(2*len, &q);
	p = scm_to_locale_string(STR);
	for (i = 0; i < len; i++) {
		q[i << 1] = xlet[p[i] >> 4];
		q[(i << 1) + 1] = xlet[p[i] & 0x0f];
	}
	free(p);
	return ret;
}
#undef FUNC_NAME

void
rscm_hash_init()
{
#include <rscm_hash.x>
}
