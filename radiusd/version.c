/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* $Id$ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <radiusd.h>

static char *sys_def[] = {
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
	"FreeBSD",
#endif
#if defined(__NetBSD__)
	"NetBSD",
#endif
#if defined(__OpenBSD__)
        "OpenBSD",
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
	NULL
};

static char *debug_flag_str[] = {
#if defined(MAINTAINER_MODE)
	"MAINTAINER_MODE",
#endif
	NULL
};

static char *compile_flag_str[] = {
#if defined(PWD_SHADOW)
	"PWD_SHADOW",
#endif
#if defined(USE_SERVER_GUILE)
	"USE_SERVER_GUILE",
#endif
#if defined(USE_PAM)
	"USE_PAM",
#endif
#if defined(USE_DBM)
# if USE_DBM == DBM_DBM	
	"USE_DBM=DBM",
# elif USE_DBM == DBM_NDBM
	"USE_DBM=NDBM",
# endif
#endif /* USE_DBM */
#ifdef USE_SQL_MYSQL
	"USE_SQL_MYSQL",
#endif	    
#ifdef USE_SQL_POSTGRES
	"USE_SQL_POSTGRES",
#endif	
#ifdef USE_SQL_ODBC
	"USE_SQL_ODBC",
#endif	
#if defined(USE_SNMP)
	"USE_SNMP",
#endif
#if defined(USE_LIVINGSTON_MENUS)
	"USE_LIVINGSTON_MENUS",
#endif
#if defined(DENY_SHELL)
	"DENY_SHELL",
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
	NULL
};


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
 * Display the version number and built-in defaults.
 */
void
version()
{
	int i;
	
	printf(_("%s: GNU Radius version %s"), progname, VERSION);
#ifdef BUILD_TARGET
	printf(" (%s)", BUILD_TARGET);
#endif
	printf("\n");

	printf(_("Compilation platform: "));
	for (i = 0; sys_def[i]; i++)
		printf("%s ", sys_def[i]);

	printf(_("\nDebugging flags: "));
	for (i = 0; debug_flag_str[i]; i++) {
		printf("%s ", debug_flag_str[i]);
	}

	printf(_("\nCompilation flags: "));
	for (i = 0; compile_flag_str[i]; i++) {
		printf("%s ", compile_flag_str[i]);
	}
	printf("\n");
	printf("Ports in use:\n");
	printf(" AUTH: %d\n", DEF_AUTH_PORT);
	printf(" ACCT: %d\n", DEF_ACCT_PORT);
#if defined(USE_MYSQL)
	printf(" SQL : %d\n", RAD_SQL_PORT);
#endif
	printf("Paths:\n");
	printf(_(" configuration directory: %s\n"), RADIUS_DIR);
	printf(_(" logging directory:       %s\n"), RADLOG_DIR);
	printf(_(" accounting directory:    %s\n"), RADACCT_DIR);
#if defined(DENY_SHELL)
	printf(_(" deny shell:              %s\n"), DENY_SHELL);
#endif

#ifdef RADIUS_PID
	printf(_(" pidfile:                 %s\n"), RADIUS_PID);
#else
	printf(_(" no pidfile\n"));
#endif

	printf("\nReport bugs to <%s>\n", bug_report_address);
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
	printf("%s: Copyright 1999,2000,2001 Sergey Poznyakoff\n", progname);
	printf("\nThis program is part of GNU Radius\n");
	printf("%s", license_text);
}
