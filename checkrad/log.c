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
#include <errno.h>
#include <syslog.h>

#include <sysdep.h>
#include <radiusd.h>

int debug_flag;
int log_pid;
char *progname;
FILE *logfile;

void
initlog(name)
	char *name;
{
	progname = strrchr(name, '/');
	if (progname)
		progname++;
	else
		progname = name;
	log_pid = getpid();
}

void 
set_logfile(s)
	char *s;
{
	logfile = fopen(s, "a");
	if (!logfile) {
		syslog(LOG_ERR, _("can't open %s for logging: %m"), s);
		logfile = stderr;
		return;
	}
}

static int do_log(int lvl, int syserr, char *fmt, va_list ap);

int
do_log(lvl, syserr, fmt, ap)
	int lvl;
	int syserr;
	char *fmt;
	va_list ap;
{
	unsigned char *s = "";
	int errnum = errno;
	time_t timeval;
	struct tm *tm;
	char timebuf[64];

	if (!logfile)
		logfile = stderr;
	timeval = time(NULL);
	tm = localtime(&timeval);
	strftime(timebuf, sizeof(timebuf), "%b %d %H:%M:%S", tm);
	fprintf(logfile, "%s: %s[%d]: ", timebuf, progname, log_pid);

	switch(lvl) {
	case L_DBG:
		s = N_("Debug");
		break;
	case L_AUTH:
		s = N_("Auth");
		break;
	case L_PROXY:
		s = N_("Proxy");
		break;
	case L_INFO:
		s = N_("Info");
		break;
	case L_ERR:
		s = N_("Error");
		break;
        case L_WARN:
		s = N_("Warning");
		break;
	case L_NOTICE:
		s = N_("Notice");
		break;
	case L_CRIT:
		s = N_("Crit");
		break;
	}
	fprintf(logfile, "%s: ", _(s));
	vfprintf(logfile, fmt, ap);
	if (syserr)
		fprintf(logfile, ": %s", strerror(errnum));
        fprintf(logfile, "\n");
	fflush(logfile);

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

int
debug_printf(msg, va_alist)
	char *msg;
	va_dcl
{
	va_list ap;
	int r = 0;

	va_start(ap);
	r = do_log(L_DBG, 0, msg, ap);
	va_end(ap);
	return r;
}







