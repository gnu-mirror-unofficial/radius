/* $Id$ */

#undef PW_AUTH_UDP_PORT
#undef PW_ACCT_UDP_PORT

/* Target RADIUS was built for */
#undef BUILD_TARGET 
/* System configuration files directory */
#undef ETC_DIR
/* Directory where RADIUS stores its logfiles */
#undef RADLOG_DIR
/* Directory for pidfile */
#undef RADPID_DIR

#define SQL_MYSQL    1
#define SQL_POSTGRES 2

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

/* ************************************************************************** */
/* data types that might be missed */
#undef off_t
#undef u_char
#undef u_int
#undef u_long
/* ************************************************************************** */

#undef HAVE_SYS_ERRLIST

#undef HAVE_LIBDBM

#undef HAVE_LIBNDBM

#undef HAVE_LIBPAM

#undef HAVE_LIBMYSQL

#undef HAVE_LIBPQ

/* Define this to disable shadow support */
#undef PWD_SHADOW

/* Enable OSFC2 */
#undef OSFC2

/* If defined users with Auth-Type=System and login shell = DENY_SHELL will */
/* alwys be denied access */
#undef DENY_SHELL

/* Define this to enable SNMP support */
#undef USE_SNMP

/* Define this to enable SQL support */
#undef USE_SQL 

/* Define this to enable MYSQL subsystem of SQL support */
#undef USE_SQL_MYSQL

/* Define this to enable Livingston-compatible menus */
#undef USE_LIVINGSTON_MENUS

/* Define this to enable notification */
#undef USE_NOTIFY

/* Port to use to connect to MYSQL */
/* leave undefined to use default one */
#undef RAD_MYSQL_PORT

/* Define this to enable PAM support */
#undef USE_PAM

/* Define this if you wish the DBM support */
#undef USE_DBM

#undef DBM

#undef NDBM

#undef YACC_DEBUG

#if defined(sun)
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
