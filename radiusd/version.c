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
/* $Id$ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include        <sys/types.h>
#include	<stdio.h>
#include	<radiusd.h>

static char *sys_def[] = {
	/* here are all the system definitions compilation uses */
#if defined(__alpha)
	"__alpha",
#endif
#if defined(__osf__)
	"__osf__",
#endif
#if defined(aix)
	"aix",
#endif
#if defined(bsdi)
	"bsdi",
#endif
#if defined(__FreeBSD__)
	"FreeBSD"
#endif
#if defined(__NetBSD__)
	"NetBSD"
#endif
#if defined(sun)
	"sun",
#endif
#if defined(sys5)
	"sys5",
#endif
#if defined(unixware)
	"unixware",
#endif
#if defined(__linux__)
	"linux",
#endif
#if defined(M_UNIX)
	"M_UNIX",
#endif
};

static char *debug_flag_str[] = {
#if defined(MAINTAINER_MODE)
	"MAINTAINER_MODE",
#endif
#if defined(YACC_DEBUG)
	"YACC_DEBUG",
#endif
};

static char *compile_flag_str[] = {
#if defined(PWD_SHADOW)
	"PWD_SHADOW",
#endif
#if defined(USE_PAM)
	"USE_PAM",
#endif
#if defined(DBM)
	"DBM",
#endif
#if defined(NDBM)
	"NDBM",
#endif
#if defined(USE_SQL)	
# if defined(USE_SQL_MYSQL)
	"USE_SQL_MYSQL",
# endif	
#endif /* defined(USE_SQL) */
#if defined(USE_SNMP)
	"USE_SNMP",
#endif
#if defined(USE_NOTIFY)
	"USE_NOTIFY",
#endif
#if defined(USE_LIVINGSTON_MENUS)
	"USE_LIVINGSTON_MENUS",
#endif
#if defined(DENY_SHELL)
	"DENY_SHELL",
#endif
#if defined(ATTRIB_NMC)
	"ATTRIB_NMC",
#endif
#if defined(OSFC2)
	"OSFC2",
#endif
#if defined(NT_DOMAIN_HACK)
	"NT_DOMAIN_HACK",
#endif
#if defined(SPECIALIX_JETSTREAM_HACK)
	"SPECIALIX_JETSTREAM_HACK",
#endif
#if defined(ASCEND_PORT_HACK)
	"ASCEND_PORT_HACK",
#endif
};

#define NITEMS(a) sizeof(a)/sizeof((a)[0])

char *server_id;

/* ************************************************************************ */

/* FIXME?:
 * Allow for expandable characters:
 *  %s - Server type (Auth/Acct/Stat)
 *  %v - Server version
 *  %h - hostname
 */
char *
make_server_ident()
{
	if (server_id)
		return estrdup(server_id);
	else {
		char *msg = _("GNU RADIUS server version ");
		int len = strlen(msg) + sizeof(VERSION);
		char *p = emalloc(len);
		sprintf(p, "%s%s", msg, VERSION);
		return p;
	}
}

/*
 *	Display the revision number for this program
 */
void
version()
{
	int i;
	
	fprintf(stderr, _("%s: GNU Radius version %s"), progname, VERSION);
#ifdef BUILD_TARGET
	fprintf(stderr, " (%s)", BUILD_TARGET);
#endif
	fprintf(stderr, "\n");

	fprintf(stderr, _("Compilation platform: "));
	for (i = 0; i < NITEMS(sys_def); i++)
		fprintf(stderr, "%s ", sys_def[i]);

	fprintf(stderr, _("\nDebugging flags: "));
	for (i = 0; i < NITEMS(debug_flag_str); i++) {
		fprintf(stderr, "%s ", debug_flag_str[i]);
	}

	fprintf(stderr, _("\nCompilation flags: "));
	for (i = 0; i < NITEMS(compile_flag_str); i++) {
		fprintf(stderr, "%s ", compile_flag_str[i]);
	}
	fprintf(stderr, "\n");
#if defined(USE_MYSQL)
	fprintf(stderr, "using mysql port %d\n", RAD_MYSQL_PORT);
#endif
#if defined(DENY_SHELL)
	fprintf(stderr, _("deny shell is %s\n"), DENY_SHELL);
#endif
	fprintf(stderr, _("logfiles stored in %s\n"), RADLOG_DIR);

#ifdef RADIUS_PID
	fprintf(stderr, _("pidfile %s\n"), RADIUS_PID);
#else
	fprintf(stderr, _("no pidfile\n"));
#endif

	exit(0);
}

char license_text[] =
"   This program is free software; you can redistribute it and/or modify\n"
"   it under the terms of the GNU General Public License as published by\n"
"   the Free Software Foundation; either version 2, or (at your option)\n"
"   any later version.\n"
"\n"
"   This program is distributed in the hope that it will be useful,\n"
"   but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"   GNU General Public License for more details.\n"
"\n"
"   You should have received a copy of the GNU General Public License\n"
"   along with this program; if not, write to the Free Software\n"
"   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n";

void
license()
{
	printf("%s: Copyright 1999,2000 Sergey Poznyakoff\n", progname);
	printf("\nThis program is part of GNU Radius\n");
	printf("%s", license_text);
}
