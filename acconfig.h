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

#undef HAVE_SYS_ERRLIST

#undef HAVE_LIBDBM

#undef HAVE_LIBNDBM

#undef HAVE_LIBPAM

#undef HAVE_LIBMYSQL

/* Define this to disable shadow support */
#undef PWD_SHADOW

/* Enable OSFC2 */
#undef OSFC2

/* Vendor-specific attributes */
#undef ATTRIB_NMC

#undef NO_ATTRIB_NMC

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

#ifndef ATTRIB_NMC
# ifndef NO_ATTRIB_NMC
#  define ATTRIB_NMC
# endif
#endif

/* Hack for funky ascend ports on MAX 4048 (and probably others)
 * The "NAS-Port-Id" value is "xyyzz" where "x" = 1 for digital, 2 for analog;
 *  "yy" = line number (1 for first PRI/T1/E1, 2 for second, so on);
 *  "zz" = channel number (on the PRI or Channelized T1/E1).
 * This should work with normal terminal servers, unless you have a TS with
 * more than 9999 ports ;^).
 * The "ASCEND_CHANNELS_PER_LINE" is the number of channels for each line into
 * the unit.  For my US/PRI that's 23.  A US/T1 would be 24, and a
 * European E1 would be 30 (I think ... never had one ;^).
 * This will NOT change the "NAS-Port-Id" reported in the detail log.  This
 * is simply to fix the dynamic IP assignments a la Cistron.
 * WARNING: This hack works for me, but I only have one PRI!!!  I've not
 *          tested it on 2 or more (or with models other than the Max 4048)
 * Use at your own risk!
 * -- dgreer@austintx.com
 */
#undef ASCEND_PORT_HACK 
#undef ASCEND_CHANNELS_PER_LINE 
#ifdef ASCEND_PORT_HACK
# ifndef ASCEND_CHANNELS_PER_LINE
#  define ASCEND_CHANNELS_PER_LINE 23
# endif
#endif

#undef RADIUS_DEBUG

#undef __FUNCTION__

#ifdef MAINTAINER_MODE
# define LEAK_DETECTOR 1
# ifdef lint
#  define __extension__(c) 1
# endif
#endif
