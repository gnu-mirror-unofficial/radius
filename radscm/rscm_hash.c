/* This file is part of GNU Radius.
   Copyright (C) 2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
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
	   "FIXME")
#define FUNC_NAME s_rscm_md5_calc
{
	char digest[AUTH_VECTOR_LEN];
	
	SCM_ASSERT (SCM_NIMP(INPUT) && SCM_STRINGP(INPUT),
		    INPUT, SCM_ARG1, FUNC_NAME);
	grad_md5_calc(digest, SCM_STRING_CHARS(INPUT),
		      SCM_STRING_LENGTH(INPUT));
	return scm_mem2string(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_md4_calc, "md4-calc", 1, 0, 0,
           (SCM INPUT),
	   "FIXME")
#define FUNC_NAME s_rscm_md4_calc
{
	char digest[16];
	
	SCM_ASSERT(SCM_NIMP(INPUT) && SCM_STRINGP(INPUT),
		   INPUT, SCM_ARG1, FUNC_NAME);
	grad_md4_calc(digest, SCM_STRING_CHARS(INPUT),
		      SCM_STRING_LENGTH(INPUT));
	return scm_mem2string(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_sha1_calc_list, "sha1-calc-list", 1, 0, 0,
           (SCM HLIST),
	   "FIXME")
#define FUNC_NAME s_rscm_sha1_calc_list
{
	unsigned char *input;
	size_t length;
	char digest[20];
	SHA1_CTX ctx;
	
	SCM_ASSERT(SCM_NIMP(HLIST) && SCM_CONSP(HLIST),
		   HLIST, SCM_ARG1, FUNC_NAME);
	SHA1Init(&ctx);
	for(; SCM_CONSP(HLIST); HLIST = SCM_CDR(HLIST)) {
		SCM car = SCM_CAR(HLIST);
		
		SCM_ASSERT(SCM_NIMP(car) && SCM_STRINGP(car),
			   car, SCM_ARG1, FUNC_NAME);
		SHA1Update(&ctx, SCM_STRING_CHARS(car),
			   SCM_STRING_LENGTH(car));
	}
	SHA1Final(digest, &ctx);
	return scm_mem2string(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_lm_password_hash, "lm-password-hash", 1, 0, 0,
           (SCM INPUT),
	   "FIXME")
#define FUNC_NAME s_rscm_lm_password_hash
{
	unsigned char digest[72];
	SCM_ASSERT(SCM_NIMP(INPUT) && SCM_STRINGP(INPUT),
		   INPUT, SCM_ARG1, FUNC_NAME);
	grad_lmpwdhash(SCM_STRING_CHARS(INPUT), digest);
	return scm_mem2string(digest, sizeof digest);
}
#undef FUNC_NAME

SCM_DEFINE(rscm_mschap_response, "mschap-response", 2, 0, 0,
           (SCM PASSWORD, SCM CHALLENGE),
	   "FIXME")
#define FUNC_NAME s_rscm_mschap_response
{
	unsigned char digest[24];
	SCM_ASSERT(SCM_NIMP(PASSWORD) && SCM_STRINGP(PASSWORD),
		   PASSWORD, SCM_ARG1, FUNC_NAME);
	SCM_ASSERT(SCM_NIMP(CHALLENGE) && SCM_STRINGP(CHALLENGE),
		   CHALLENGE, SCM_ARG2, FUNC_NAME);
	grad_mschap(SCM_STRING_CHARS(PASSWORD),
		    SCM_STRING_CHARS(CHALLENGE),
		    digest);
	return scm_mem2string(digest, sizeof digest);
}
#undef FUNC_NAME

static const char *xlet = "0123456789ABCDEF";

SCM_DEFINE(rscm_string_hex_to_bin, "string-hex->bin", 1, 0, 0,
           (SCM STR),
	   "FIXME")
#define FUNC_NAME s_rscm_string_hex_to_bin
{
	int i, len;
	unsigned char *p, *q;
	SCM ret;

	SCM_ASSERT(SCM_NIMP(STR) && SCM_STRINGP(STR),
		   STR, SCM_ARG1, FUNC_NAME);
	len = SCM_STRING_LENGTH(STR);
	if (len % 2)
		scm_misc_error(FUNC_NAME,
			       "Input string has odd length",
			       SCM_EOL);
	len /= 2;
	ret = scm_allocate_string(len);
	p = SCM_STRING_CHARS(STR);
	q = SCM_STRING_CHARS(ret);
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
	return ret;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_string_bin_to_hex, "string-bin->hex", 1, 0, 0,
           (SCM STR),
	   "FIXME")
#define FUNC_NAME s_rscm_string_bin_to_hex
{
	int i, len;
	unsigned char *p, *q;
	SCM ret;

	SCM_ASSERT(SCM_NIMP(STR) && SCM_STRINGP(STR),
		   STR, SCM_ARG1, FUNC_NAME);
	len = SCM_STRING_LENGTH(STR);
	ret = scm_allocate_string(2*len);
	p = SCM_STRING_CHARS(STR);
	q = SCM_STRING_CHARS(ret);
	for (i = 0; i < len; i++) {
		q[i << 1] = xlet[p[i] >> 4];
		q[(i << 1) + 1] = xlet[p[i] & 0x0f];
	}
	return ret;
}
#undef FUNC_NAME

void
rscm_hash_init()
{
#include <rscm_hash.x>
}
