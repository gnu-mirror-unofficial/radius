/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2003 Sergey Poznyakoff
  
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radius.h>

/*PRINTFLIKE2*/
void
radlog
#if STDC_HEADERS
      (int lvl, const char *msg, ...)
#else	
      (lvl, msg, va_alist)
        int lvl;
        const char *msg;
        va_dcl
#endif
{
        va_list ap;
        int ec = 0;

        if (lvl & L_PERROR)
                ec = errno;
#if STDC_HEADERS	
        va_start(ap, msg);
#else
        va_start(ap);
#endif
        vlog(lvl, NULL, 0, NULL, ec, msg, ap);
        va_end(ap);
}

/* Try to represent a request as fully as possible.
   General format is:

     REQ-TYPE ":" NAS-ID ":" REQ-ID [ ";" REQ-DATA ] "[" USER-NAME "]"

   REQ-TYPE := "AUTH" | "ACCT"
   NAS-ID := Name of the NAS from naslist or its FQDN, or its IP in dotted-quad
   notation.
   REQT-ID := <NUMBER> -- The request identifier.

   If REQ-TYPE is "AUTH", then REQ-DATA is empty. Otherwise,

   REQ-DATA := ACCT-STATUS ";" ACCT-SESSION-ID 

   e.g.:
   
   AUTH:nas2:345[uname]
   ACCT:nas2:346;Start;01012456[uname]

   The maximum length of the output buffer is

   4+1+MAX_LONGNAME+1+4+2*AUTH_STRING_LEN+3+1+AUTH_STRING_LEN+1+1 = 1031 bytes
*/

char *
rad_print_request(req, outbuf, size)
	RADIUS_REQ *req;
	char *outbuf;
	size_t size;
{
	char nasbuf[MAX_LONGNAME];
	VALUE_PAIR *stat_pair, *name_pair;
	char sbuf[2*AUTH_STRING_LEN+3];

	sbuf[0] = 0;
	stat_pair = avl_find(req->request, DA_ACCT_STATUS_TYPE);
	if (stat_pair) {
		VALUE_PAIR *sid_pair = avl_find(req->request,
						DA_ACCT_SESSION_ID);
		DICT_VALUE *dval = value_lookup(stat_pair->avp_lvalue,
						"Acct-Status-Type");
		char nbuf[64], *stat;

		if (dval)
			stat = dval->name;
		else {
			snprintf(nbuf, sizeof nbuf, "%ld", sid_pair->avp_lvalue);
			stat = sbuf;
		}
				 
		snprintf(sbuf, sizeof sbuf,
			 " %s %s",
			 stat, sid_pair ? sid_pair->avp_strvalue : "(none)");
	}

	name_pair = avl_find(req->request, DA_USER_NAME);
	snprintf(outbuf, size, "(%s %s %d %s%s)",
		 auth_code_abbr(req->code),
		 nas_request_to_name(req, nasbuf, sizeof nasbuf),
		 req->id,
		 name_pair ? name_pair->avp_strvalue : "[none]",
		 sbuf);
	return outbuf;
}

/*PRINTFLIKE3*/
void
radlog_req
#if STDC_HEADERS
           (int lvl, RADIUS_REQ *req, const char *msg, ...)
#else
	   (lvl, req, msg, va_alist)
        int lvl;
	RADIUS_REQ *req;
        const char *msg;
        va_dcl
#endif
{
	va_list ap;

#if STDC_HEADERS	
	va_start(ap, msg);
#else
	va_start(ap);
#endif
	if (req) {
		char idbuf[MAXIDBUFSIZE];
		char *buf = NULL;

		vasprintf(&buf, msg, ap);
	
		radlog(lvl, "%s: %s",
		       rad_print_request(req, idbuf, sizeof idbuf),
		       buf);
		free(buf);
	} else {
		int ec = 0;

		if (lvl & L_PERROR)
			ec = errno;
		vlog(lvl, NULL, 0, NULL, ec, msg, ap);
	}		
	va_end(ap);
}

void
_dolog
#if STDC_HEADERS
      (int level, char *file, int line, char *func_name, char *fmt, ...)
#else
      (level, file, line, func_name, fmt, va_alist)
        int level;
        char *file;
        int line;
        char *func_name;
        char *fmt;
        va_dcl
#endif
{
        va_list ap;
        int ec = 0;
        
        if (level & L_PERROR)
                ec = errno;
#if STDC_HEADERS	
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
        vlog(level, file, line, func_name, ec, fmt, ap);
        va_end(ap);
}

void
_debug_print(file, line, func_name, str)
        char *file;
        int line;
        char *func_name;
        char *str;
{
        _dolog(L_DEBUG, file, line, func_name, "%s", str);
        free(str);
}

/*VARARGS*/
char *
_debug_format_string
#if STDC_HEADERS
                    (char *fmt, ...)
#else
                    (va_alist)
        va_dcl
#endif
{
        va_list ap;
        char *str = NULL;
#if !STDC_HEADERS
        char *fmt;
	
        va_start(ap);
        fmt = va_arg(ap,char*);
#else
	va_start(ap, fmt);
#endif
        vasprintf(&str, fmt, ap);
        va_end(ap);
        return str;
}
