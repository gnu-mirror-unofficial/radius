/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2003 Free Software Foundation, Inc.

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radius.h>

/*PRINTFLIKE2*/
void
radlog (int lvl, const char *msg, ...)
{
        va_list ap;
        int ec = 0;

        if (lvl & L_PERROR)
                ec = errno;
        va_start(ap, msg);
        vlog(lvl, NULL, NULL, NULL, ec, msg, ap);
        va_end(ap);
}

/*PRINTFLIKE3*/
void
radlog_req(int lvl, RADIUS_REQ *req, const char *msg, ...)
{
        va_list ap;
        int ec = 0;

        if (lvl & L_PERROR)
                ec = errno;
        va_start(ap, msg);
        vlog(lvl, req, NULL, NULL, ec, msg, ap);
        va_end(ap);
}

void
radlog_loc(int lvl, LOCUS *loc, const char *msg, ...)
{
	va_list ap;
	int ec = 0;

	if (lvl & L_PERROR)
		ec = errno;

	va_start(ap, msg);
	vlog(lvl, NULL, loc, NULL, ec, msg, ap);
	va_end(ap);
}

void
_dolog(int level, char *file, size_t line, char *func_name, char *fmt, ...)
{
        va_list ap;
        int ec = 0;
        LOCUS loc;

        if (level & L_PERROR)
                ec = errno;
	loc.file = file;
	loc.line = line;
	va_start(ap, fmt);
        vlog(level, NULL, &loc, func_name, ec, fmt, ap);
        va_end(ap);
}

void
_debug_print(char *file, size_t line, char *func_name, char *str)
{
        _dolog(L_DEBUG, file, line, func_name, "%s", str);
        free(str);
}

/*VARARGS*/
char *
_debug_format_string(char *fmt, ...)
{
        va_list ap;
        char *str = NULL;

	va_start(ap, fmt);
        vasprintf(&str, fmt, ap);
        va_end(ap);
        return str;
}
