/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

/* log.c	Logging module. */
static char rcsid[] = 
"$Id$";

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <varargs.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radiusd.h>

int debug_flag;
char *progname;

void
initlog(name)
	char *name;
{
	progname = strrchr(name, '/');
	if (progname)
		progname++;
	else
		progname = name;
}

static int do_log(int lvl, int syserr, char *fmt, va_list ap);

int
do_log(lvl, syserr, fmt, ap)
	int lvl;
	int syserr;
	char *fmt;
	va_list ap;
{
	unsigned char	*s = ":";
	int errnum = errno;

	fprintf(stderr, "%s: ", progname);
	switch (lvl) {
	case L_DBG:
		s = "Debug: ";
		break;
	case L_AUTH:
		s = "Auth: ";
		break;
	case L_PROXY:
		s = "Proxy: ";
		break;
	case L_INFO:
		s = "Info: ";
		break;
	case L_WARN:
		s = "Warning: ";
		break;
	case L_ERR:
		s = "Error: ";
		break;
	case L_CRIT:
		s = "CRIT: ";
		break;
	}
	fprintf(stderr, s);
	vfprintf(stderr, fmt, ap);
	if (syserr)
		fprintf(stderr, ": %s", strerror(errnum));
        fprintf(stderr, "\n");

	return 0;
}

int
radlog(lvl, msg, va_alist)
	int lvl;
	char *msg;
	va_dcl
{
	va_list ap;
	int r;

	r = lvl & L_PERROR;
	lvl &= L_MASK;
	va_start(ap);
	do_log(lvl, r, msg, ap);
	va_end(ap);

	return 0;
}

