/* This file is part of GNU Radius.
   Copyright (C) 2007,2008 Free Software Foundation, Inc.

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
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <common.h>
#include <argp.h>

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
		    const grad_request_t *req,
		    const grad_locus_t *loc,
		    const char *func_name, int en,
		    const char *fmt, va_list ap)
{
        fprintf(stderr, "%s: %s: ", program_invocation_short_name,
		priname[level & GRAD_LOG_PRIMASK]);
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

