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

int debug_flag;

#define SP(p) ((p)?(p):"")

static char *priname[] = { /* priority names */
        "emerg",
        "alert",
        "crit",
        "error",
        "warning",
        "notice",
        "info",
        "debug"
};

void
grad_default_logger(int level, 
     const RADIUS_REQ *req,
     const LOCUS *loc,
     const char *func_name, int en,
     const char *fmt, va_list ap)
{
        fprintf(stderr, "%s: %s: ", program_invocation_short_name,
		priname[level & L_PRIMASK]);
        if (loc) {
                fprintf(stderr, "%s:%lu:", loc->file, (unsigned long) loc->line);
		if (func_name)
			fprintf(stderr, "%s:", func_name);
		fprintf(stderr, " ");
	}
        vfprintf(stderr, fmt, ap);
        if (en)
                fprintf(stderr, ": %s", strerror(en));
        fprintf(stderr, "\n");
}



static grad_logger_fp _grad_logger = grad_default_logger;

grad_logger_fp
grad_set_logger(grad_logger_fp fp)
{
	grad_logger_fp tmp = _grad_logger;
	_grad_logger = fp;
	return tmp;
}

/*PRINTFLIKE2*/
void
radlog(int lvl, const char *msg, ...)
{
        va_list ap;
        int ec = 0;

        if (lvl & L_PERROR)
                ec = errno;
        va_start(ap, msg);
        _grad_logger(lvl, NULL, NULL, NULL, ec, msg, ap);
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
        _grad_logger(lvl, req, NULL, NULL, ec, msg, ap);
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
	_grad_logger(lvl, NULL, loc, NULL, ec, msg, ap);
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
        _grad_logger(level, NULL, &loc, func_name, ec, fmt, ap);
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
