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

#undef DEF_AUTH_PORT
#undef DEF_ACCT_PORT

/* Target RADIUS was built for */
#undef BUILD_TARGET 
/* System configuration files directory */
#undef ETC_DIR
/* Directory where RADIUS stores its logfiles */
#undef RADLOG_DIR
/* Directory for pidfile */
#undef RADPID_DIR

#define DBM_DBM  1
#define DBM_NDBM 2


@TOP@

@BOTTOM@

#undef USE_NLS

/* ************************************************************************** */
/* Internationalization support */
#if defined(USE_NLS) && defined(HAVE_LIBINTL)
# include <libintl.h>
# define _(s) gettext(s)
#else
# define _(s) s
#endif
#define N_(s) s

/* ************************************************************************* */
/* data types and definitions that might be missed */
#undef off_t
#undef u_char
#undef u_int
#undef u_long
#undef INADDR_LOOPBACK
/* ************************************************************************* */


#undef HAVE_GNU_GETOPT

#undef HAVE_SYS_ERRLIST

#undef HAVE_LIBDBM

#undef HAVE_LIBNDBM

#undef HAVE_LIBPAM

#undef HAVE_LIBMYSQL

#undef HAVE_LIBPQ

#undef HAVE_LIBODBC

/* Define this to disable shadow support */
#undef PWD_SHADOW

/* Enable OSFC2 */
#undef OSFC2

/* If defined users with Auth-Type=System and login shell = DENY_SHELL will */
/* alwys be denied access */
#undef DENY_SHELL

/* Define this to enable Guile interface */
#undef USE_SERVER_GUILE

/* Define this to enable SNMP support */
#undef USE_SNMP

/* Define this to enable SNMP oids, compatible with versions 0.95 and 0.96 */
#undef SNMP_COMPAT_0_96

/* Define this to enable SQL support */
#undef USE_SQL 

/* Define this to enable MYSQL subsystem of SQL support */
#undef USE_SQL_MYSQL

/* Define this to enable POSTGRES subsystem of SQL support */
#undef USE_SQL_POSTGRES

/* Define this to enable ODBC subsystem of SQL support */
#undef USE_SQL_ODBC

/* Define this to enable Livingston-compatible menus */
#undef USE_LIVINGSTON_MENUS

/* Port to use to connect to MYSQL */
/* leave undefined to use default one */
#undef RAD_MYSQL_PORT

/* Define this to enable PAM support */
#undef USE_PAM

/* Define this if you wish the DBM support */
#undef USE_DBM

#if defined(sun) && !defined(__EXTENSIONS__)
# define __EXTENSIONS__
#endif

#ifndef STAT_MAX_NAS_COUNT
# define STAT_MAX_NAS_COUNT 128
#endif
#ifndef STAT_MAX_PORT_COUNT
# define STAT_MAX_PORT_COUNT 1024
#endif

#undef RADIUS_DEBUG

#undef __FUNCTION__

#ifdef MAINTAINER_MODE
# define LEAK_DETECTOR 1
# ifdef lint
#  define __extension__(c) 1
# endif
#endif

#ifdef RADIUS_DEBUG
# include <debugmod.h>
#endif
