# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_PREREQ(2.53)

AC_REVISION($Revision$)
AC_INIT(GNU Radius, 0.99.97, bug-gnu-radius@gnu.org, gnu-radius)
AC_CONFIG_SRCDIR(radiusd/radiusd.c)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(no-exeext)
AM_CONFIG_HEADER(config.h)

AC_SUBST(BUILD_TARGET)
AC_SUBST(INCLUDEPATH)
AC_SUBST(YACC_OPTS)
AC_SUBST(RADLOG_DIR)
AC_SUBST(RADIUS_PID)
AC_SUBST(PS)
AC_SUBST(GETOPT)

case $target in
	*-*-linux*)	SHADOW_SUPPORT=yes
			ST="BSD";;

	*-*-solaris*)   SHADOW_SUPPORT=yes
                        ST="SYSV";;

	*-*-*bsd*)	ST="BSD";;

        *)              ST="BSD";;
esac

## * Checks for programs.
AC_PROG_CC
AM_PROG_CC_STDC
AC_PROG_RANLIB
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_AWK

dnl Override a bug in autoconf 2.53: AS_LITERAL_IF incorrectly optimizes
dnl out ac_dummy indirection if the argument has shell variables in it.
dnl To compensate, I have to use my own dummy variable.

ra_PATH=$PATH:/usr/ccs/bin:/usr/bin:/usr/local/bin
AC_PATH_PROG(M4, m4, no, $ra_PATH)
AC_PATH_PROG(PS, ps, no, $ra_PATH)
AC_PATH_PROG(GETOPT, getopt, no, $ra_PATH)
AC_PROG_LN_S
AM_PROG_LIBTOOL

AC_SUBST(build_POFILTER)
RA_MAINTAINER_MODE([build_POFILTER=pofilter])

### Make sure Guile is installed.
AC_ARG_WITH(guile,
	[  --without-guile                do not compile Guile support],
        [USE_GUILE=$withval],
        [USE_GUILE=yes])

AC_ARG_WITH(server-guile,
	[  --with-server-guile            compile server Guile support (WARNING: see README for details)],
        [USE_SERVER_GUILE=$withval],
        [USE_SERVER_GUILE=0])

if test $USE_GUILE = yes; then
	RA_CHECK_GUILE(,
			[LIBRADSCM="libradscm.a libservscm.a"
                         RADSCM=radscm
			 RADSESSION=radsession
			 RADSCM_BUILT_SOURCES_LIST='$(DOT_X_FILES) $(DOT_DOC_FILES)'
			 GUILE_PROCEDURES_TXT=guile-procedures.txt
			 if test $USE_SERVER_GUILE = yes; then
				AC_DEFINE(USE_SERVER_GUILE,1,
                                    [Define this to enable Guile interface])
				RA_RADIUSD_LDADD(../radscm/libradscm.a ../radscm/libservscm.a $GUILE_LIBS)
			 fi],
                        [USE_GUILE=no])
fi

case "$GUILE_VERSION" in
	14) GUILE_SNARF_VERSION="1.4";;
	16|17) GUILE_SNARF_VERSION="1.6";;
	*) GUILE_SNARF_VERSION="1.6";;
esac
AC_SUBST(GUILE_INCLUDES)
AC_SUBST(GUILE_LIBS)
AC_SUBST(GUILE_SNARF_VERSION)
AC_SUBST(LIBRADSCM)
AC_SUBST(RADSCM)
AC_SUBST(RADSESSION)
AC_SUBST(RADSCM_BUILT_SOURCES_LIST)
AC_SUBST(GUILE_PROCEDURES_TXT)

### Check for Emacs site-lisp directory
AM_PATH_LISPDIR

## * Check for preprocessor capabilities
AC_MSG_CHECKING(whether compiler defines __FUNCTION__)
AC_TRY_RUN(
main() { return strcmp(__FUNCTION__,"main"); },
	AC_MSG_RESULT(yes),
	AC_DEFINE_UNQUOTED(__FUNCTION__, (char*)0,
                           [Defined if your compiler does not define it])
	AC_MSG_RESULT(no),
	AC_MSG_RESULT(don't know))

dnl ** AM_DISABLE_SHARED

## *************************************
## add any additional libraries/includes
## *************************************
AC_MSG_CHECKING(for additional includes)
AC_ARG_WITH(include-path,
	[  --with-include-path=PATH      specify additional include paths.
                                         PATH is a ':' separated list of additional
                                         include paths.  ],
	[ for path in `echo $withval | sed 's/:/ /g'`
          do
            INCLUDEPATH="$INCLUDEPATH -I$path"
          done])
AC_MSG_RESULT($INCLUDEPATH)

AC_MSG_CHECKING(for additional libraries)
AC_ARG_WITH(lib-path,    
	[  --with-lib-path=PATH          specify additional library paths.],
	[ for path in `echo $withval | sed 's/:/ /g'`
          do
            LIBS="$LIBS -L$path"
          done])
AC_MSG_RESULT($LIBS)

## * Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyaddr)
AC_CHECK_LIB(crypt, crypt)

HAVE_PTHREAD=no
AC_CHECK_LIB(pthread, pthread_self,
             [ HAVE_PTHREAD=yes
               LIBS="$LIBS -lpthread -lc" ],
             AC_CHECK_LIB(c_r, pthread_self,
                          [ HAVE_PTHREAD=yes
                            LIBS="$LIBS -lc_r" ]))

if test $HAVE_PTHREAD != yes; then
	AC_MSG_ERROR("POSIX threads library not found. Please install one and then reconfigure")
fi

AC_CHECK_FUNCS(pthread_atfork)

## * Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h malloc.h strings.h\
 sys/file.h sys/time.h sys/types.h unistd.h\
 ctype.h sys/socket.h netinet/in.h arpa/inet.h\
 netdb.h stdarg.h varargs.h termcap.h termios.h termio.h sgtty.h\
 crypt.h sys/uio.h sys/select.h sys/resources.h getopt.h libintl.h)

## * Check for national language support
AM_GNU_GETTEXT(use-libtool)
if test ".$BUILD_INCLUDED_LIBINTL" = ".yes" ; then
	INCLUDEPATH="$INCLUDEPATH -I\$(top_srcdir)/intl"
fi

## * Provide top and bottom parts of config.h.
AH_TOP([
#ifndef _REENTRANT
# define _REENTRANT
#endif
])

AH_BOTTOM([
/* Internationalization support */
#if defined(ENABLE_NLS) && !defined(lint)
# ifdef HAVE_LIBINTL_H
#  include <libintl.h>
# else
#  include <libgnuintl.h>
# endif
# define _(s) gettext(s)
#else
# define _(s) s
# define dgettext(domain,msgid) msgid
# deifne ngettext(s,p,n) p
#endif
#define N_(s) s

/*FIXME*/
#if defined(sun) && !defined(__EXTENSIONS__)
# define __EXTENSIONS__
#endif

#ifdef MAINTAINER_MODE
# define LEAK_DETECTOR 1
#endif

#ifdef RADIUS_DEBUG
# include <debugmod.h>
#endif
])

## * Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_CHECK_TYPE(u_char, unsigned char)
AC_CHECK_TYPE(u_int, unsigned int)
AC_CHECK_TYPE(u_long, unsigned long)
AC_HEADER_TIME
AC_STRUCT_TM
RA_CHECK_INADDR_LOOPBACK

## * Checks for library functions.
#AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(setsid gethostname gettimeofday \
 mkdir mktime select socket strdup strtol lockf \
 setlocale bzero \
 inet_ntoa inet_aton setvbuf seteuid setreuid getdtablesize) 
AC_FUNC_OBSTACK

AC_CHECK_DECLS([strncasecmp, strtok_r, localtime_r, asprintf, vasprintf, getline], , ,
               [
#define _REENTRANT
#include <string.h>
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
# ifdef TIME_WITH_SYS_TIME
#  include <time.h>
# endif
#else
# include <time.h>
#endif
#include <stdio.h>])

AC_ARG_WITH(included-argp,
	[  --with-included-argp           Use included argp library],
        [USE_INCLUDED_ARGP=$withval],
        [USE_INCLUDED_ARGP=no])

AC_CHECK_FUNCS(argp_parse, :, USE_INCLUDED_ARGP=yes)

if test $USE_INCLUDED_ARGP = yes; then
	AC_LIBOBJ([argp-ba])
        AC_LIBOBJ([argp-eexst])
        AC_LIBOBJ([argp-fmtstream])
        AC_LIBOBJ([argp-fs-xinl])
        AC_LIBOBJ([argp-help])
        AC_LIBOBJ([argp-parse])
        AC_LIBOBJ([argp-pv])
        AC_LIBOBJ([argp-pvh])
        AC_LIBOBJ([argp-xinl])
        AC_LIBOBJ([pin])
fi

AC_REPLACE_FUNCS(getline strerror strncasecmp strcspn snprintf vasprintf\
 strtok_r localtime_r strchrnul strndup strnlen)

RA_CHECK_STRUCT_FIELD(hostent, h_addr_list,
                       [#include <netdb.h>])
RA_REPLACE_GNU_GETOPT
RA_REPLACE_REGEX


AC_MSG_CHECKING(for sys_errlist and sys_nerr)
AC_TRY_RUN(
extern char *sys_errlist[[]];
extern int sys_nerr;
main() { char *s = sys_errlist[[0]]; return 0; },
	AC_DEFINE(HAVE_SYS_ERRLIST,1,
                  [Define if your system has sys_errlist global variable])
	AC_MSG_RESULT(Ok),
	AC_MSG_RESULT(No),
	AC_MSG_RESULT(don't know))

## ********************************************************************
## *                     User-configurable options                    *
## ********************************************************************

## **************
## debug
## **************
RADIUS_DEBUG=1
AC_ARG_ENABLE(debug,                     
	[  --disable-debug               disable debugging functions],
	[case $enableval in
		yes)	RADIUS_DEBUG=1;;
		no)	RADIUS_DEBUG=0;;
	 esac])

AC_DEFINE_UNQUOTED(RADIUS_DEBUG, $RADIUS_DEBUG,
                   [Define to 1 to enable debugging])

# Set ETC_DIR. I suppose it's better to be defined in config.h,
# so I do this dirty work here, instead of adding -DETC_DIR=$sysconfdir
# to every invocation of C compiler.
eval s=$sysconfdir
ETC_DIR=`echo $s|sed -e 's%NONE/%/usr/local/%'`
AC_SUBST(ETC_DIR)
AC_DEFINE_UNQUOTED(ETC_DIR, "$ETC_DIR", [Location of the /etc directory])

case "$ST" in
        "BSD")		RADLOG_DIR="/var/log"
			RADPID_DIR="/var/run"
			;;
	"SYSV")		RADLOG_DIR="/usr/adm"           
			RADPID_DIR="$ETC_DIR/raddb"
			;;
esac

AC_MSG_CHECKING(for log directory path)
AC_ARG_WITH(log-dir,
[  --with-log-dir=PATH     Use PATH instead of default log directory pah],
	[case "x$withval" in
	 x/*) RADLOG_DIR=$withval;;
         *)  AC_MSG_ERROR(Argument must be an absolute pathname);;
         esac])
AC_MSG_RESULT($RADLOG_DIR)

AC_MSG_CHECKING(for pidfile directory path)
AC_ARG_WITH(pid-dir,
[  --with-pid-dir=PATH     Use PATH instead of default podfile location],
	[case "x$withval" in
	 x/*) RADPID_DIR=$withval;;
         *)  AC_MSG_ERROR(Argument must be an absolute pathname);;
         esac])
AC_MSG_RESULT($RADPID_DIR)

AC_SUBST(RADPID_DIR)
AC_DEFINE_UNQUOTED(RADLOG_DIR,
                   "$RADLOG_DIR", [Directory to store radius log files in])
AC_DEFINE_UNQUOTED(RADPID_DIR,
                   "$RADPID_DIR", [Directory to put radius pid file in])
AC_DEFINE_UNQUOTED(BUILD_TARGET,
                   "$target", [Target the package is built for])

## ***************
## client programs
## ***************
AC_MSG_CHECKING(whether to build client programs)
AC_ARG_WITH(client,
	[  --with-client                 compile client programs],
	[BUILD_CLIENT=$withval],
	[BUILD_CLIENT=no])
AC_MSG_RESULT($BUILD_CLIENT)

## **************
## auth port no
## **************
AC_MSG_CHECKING(authentication port number)
AC_ARG_WITH(auth-port,
	[  --with-auth-port=NUMBER	 specify port number to use for authentication],
	[case $withval in
		[[0-9]][[0-9]]*)	AUTH_PORT=$withval
				;;
		rfc|RFC)	AUTH_PORT=1812
				;;	
		old|OLD)	AUTH_PORT=1645
				;;			
		*)		AC_MSG_ERROR(invalid port number)
				;;
	esac],
	AUTH_PORT=1645)
AC_MSG_RESULT($AUTH_PORT)
AC_DEFINE_UNQUOTED(DEF_AUTH_PORT, $AUTH_PORT, [Default authentication port])
AC_DEFINE_UNQUOTED(DEF_ACCT_PORT, `expr $AUTH_PORT + 1`,
                   [Default accounting port])		
		

## **************
## shadow support
## **************
AC_MSG_CHECKING(whether to enable shadow support)
AC_ARG_ENABLE(shadow,
	[  --enable-shadow	         enable shadow support],
	[case $enableval in
		yes) 	SHADOW_SUPPORT=yes;;
		*)	SHADOW_SUPPORT=no;;
	esac])
AC_MSG_RESULT($SHADOW_SUPPORT)

AH_TEMPLATE(PWD_SHADOW,1,[Define this if your system supports shadow suite])
if test x$SHADOW_SUPPORT = xyes; then
	AC_DEFINE(PWD_SHADOW)
fi

## **************
## PAM support
## **************
AC_ARG_ENABLE(pam,
	[  --enable-pam		         enable pam support],
	[case $enableval in
		yes)		USE_PAM=yes
                                AC_DEFINE(USE_PAM,1,
                                          [Enable PAM support]);;
		no)		;;
		*)		AC_MSG_ERROR(--enable-pam can't be used with an argument)
				exit 1;;
	esac])
if test x$USE_PAM = xyes; then
	AC_CHECK_LIB(pam, pam_start,
			[ AC_DEFINE(HAVE_LIBPAM,1,[Define if you have libpam]) 
               		  RA_RADIUSD_LDADD(-lpam) ],
		[ AC_MSG_ERROR(-lpam not found) 
		  exit 1])
fi


## **************
## DBM 
## **************

AH_TEMPLATE(HAVE_LIBDBM, [Define this if you have libdbm])
AH_TEMPLATE(HAVE_LIBNDBM, [Define this if you have libndbm])

rad_lib_dbm() {
	AC_CHECK_HEADER(dbm.h,,
			[ AC_MSG_ERROR(can't find header dbm.h)
			exit 0] )
	AC_CHECK_FUNC(dbminit,,			
		AC_CHECK_LIB(dbm, dbminit,
			[ AC_DEFINE(HAVE_LIBDBM) 
			  RA_RADIUSD_LDADD(-ldbm) ],
		 [ AC_MSG_ERROR(-ldbm not found) ])) 
}

rad_lib_ndbm() {
	AC_CHECK_HEADER(ndbm.h,,
			[ AC_MSG_ERROR(can't find header ndbm.h)
			exit 0] )
	AC_CHECK_FUNC(dbm_open,, 					
		AC_CHECK_LIB(ndbm, dbm_open,
			[ AC_DEFINE(HAVE_LIBNDBM) 
			  RA_RADIUSD_LDADD(-lndbm) ],
		[ AC_MSG_ERROR(-lndbm not found) ]))
}

AH_TEMPLATE(USE_DBM,[Define this to enable DBM support])
AC_ARG_ENABLE(dbm,
	[  --enable-dbm][[={dbm|ndbm}]][      include dbm support],
	[case $enableval in
		yes)	    rad_lib_ndbm
			    AC_DEFINE_UNQUOTED(USE_DBM,DBM_NDBM);;

		no)	    USE_DBM=no;;	

		DBM|dbm)    rad_lib_dbm
                            AC_DEFINE_UNQUOTED(USE_DBM,DBM_DBM);;

		NDBM|ndbm)  rad_lib_ndbm
			    AC_DEFINE_UNQUOTED(USE_DBM,DBM_NDBM);;

		*)	    AC_MSG_ERROR(unsupported option value: $enableval)
	esac])	


## **************
## SQL
## **************

BUILD_SQL=

AH_TEMPLATE(USE_SQL_MYSQL,[When defined, enable MySQL support])
AH_TEMPLATE(HAVE_LIBMYSQL,[Define if you have libmysql])
AH_TEMPLATE(USE_SQL_POSTGRES,[When defined, enable PostgreSQL support])
AH_TEMPLATE(HAVE_LIBPQ,[Define if you have libpq]) 
AH_TEMPLATE(USE_SQL_ODBC,[When defined, enable ODBC support])
AH_TEMPLATE(HAVE_LIBODBC,[Define if you have libodbc or libiodbc]) 
AH_TEMPLATE(USE_SQL,[Enables SQL support])

USE_SQL=0
AC_ARG_WITH(mysql,
        [  --with-mysql          Configure to work with MySQL],
	[case $withval in
	 yes)    RA_CHECK_LIB(mysqlclient_r, mysql_real_connect, "-lm",
                            [ USE_SQL=1
                              AC_DEFINE(USE_SQL_MYSQL)
                              AC_DEFINE(HAVE_LIBMYSQL)
                              RA_RADIUSD_LDADD($ra_cv_lib_mysqlclient_r)
                            ],
			    :,
                            [/usr/local/lib/mysql /usr/lib/mysql])

	         if test "$USE_SQL" != "1"; then
	             RA_CHECK_LIB(mysqlclient, mysql_real_connect, "-lm",
                                  [ AC_MSG_WARN([libmysqlclient_r not found. Will use libmysqlclient. Consider upgrading your MySQL.])
                                    USE_SQL=1
                                    AC_DEFINE(USE_SQL_MYSQL)
                                    AC_DEFINE(HAVE_LIBMYSQL)
                                    RA_RADIUSD_LDADD($ra_cv_lib_mysqlclient)
                                  ],
			          [ AC_MSG_ERROR(-lmysqlclient not found)],
                                  [/usr/local/lib/mysql /usr/lib/mysql])
                 fi
		;;
	 no)    ;;
        esac])

AC_ARG_WITH(postgres,
        [  --with-postgres       Configure to work with Postgres],
	[case $withval in
	 yes)	RA_CHECK_LIB(pq, PQconnectStart, [],
			    [ USE_SQL=1
                              AC_DEFINE(USE_SQL_POSTGRES)
                              AC_DEFINE(HAVE_LIBPQ) 
                              RA_RADIUSD_LDADD($ra_cv_lib_pq) ],
		            [ AC_MSG_ERROR(-lpq not found) ],
                            [/usr/local/pgsql/lib /usr/pgsql/lib])
		;;
	 no)    ;;
        esac])

rad_lib_odbc() {
RA_CHECK_LIB(odbc, SQLAllocHandle, [],
			    [ USE_SQL=1
                              AC_DEFINE(USE_SQL_ODBC)
                              AC_DEFINE(HAVE_LIBODBC) 
                              RA_RADIUSD_LDADD($ra_cv_lib_odbc) ],
		            [ AC_MSG_ERROR(-lodbc not found) ],
                            [/usr/local/lib])
}

rad_lib_iodbc() {
RA_CHECK_LIB(iodbc, SQLAllocHandle, [],
			    [ USE_SQL=1
                              AC_DEFINE(USE_SQL_ODBC)
                              AC_DEFINE(HAVE_LIBODBC) 
                              RA_RADIUSD_LDADD($ra_cv_lib_iodbc) ],
		            [ AC_MSG_ERROR(-liodbc not found) ],
                            [/usr/local/lib])
}


AC_ARG_WITH(odbc,
	[  --with-odbc][[={odbc|iodbc}]][      Configure to work with ODBC (EXPERIMENTAL)],
	[case $withval in
	 yes)			rad_lib_odbc
		;;
	 odbc|ODBC)		rad_lib_odbc
		;;
	 iodbc|iODBC|IODBC)	rad_lib_iodbc
		;;
	 no)	;;
	 *)	    		AC_MSG_ERROR(unsupported option value: $enableval)

        esac])

if test "$USE_SQL" = "1"; then
        AC_DEFINE(USE_SQL)
	BUILD_SQL=libsql.la
	SQLLIB=../sql/libsql.la
fi

AC_SUBST(BUILD_SQL)
AC_SUBST(SQLLIB)

## **************
## SNMP
## **************

AH_TEMPLATE(USE_SNMP, [Define this to enable SNMP support])
AC_ARG_ENABLE(snmp,
[  --enable-snmp][[={yes|no|compat}]][                  enable SNMP support],
	[case $enableval in
		compat)		USE_SNMP=yes
				AC_DEFINE(USE_SNMP)
				AC_DEFINE(SNMP_COMPAT_0_96,1,
                   [Enable support for MIBS used in 0.96 branch])
				;;
		yes)		USE_SNMP=yes
				AC_DEFINE(USE_SNMP)
				;;
		no)		;;
		*)		AC_MSG_ERROR(--enable-snmp can't be used with an argument)				
				exit 1;;
	esac])
	
## **************
## TTL -- retained for backward compatibility.
## **************

USE_NOTIFY=no
AC_ARG_ENABLE(notify,
	[],
	[case $enableval in
		yes)		USE_NOTIFY=yes;;
		no)		;;
	 esac])

## **************
## Directories
## **************
PAMDIR='$(prefix)/lib/security'
AC_ARG_WITH(pamdir,
	[  --with-pamdir=DIR             install PAM modiles in DIR [PREFIX/lib/security]],
	[PAMDIR=$withval])
AC_SUBST(PAMDIR)

## ***********************************************************************
## *          Compatibility options and some special hacks               *
## ***********************************************************************

AC_ARG_ENABLE(livingston-menus,
	[  --enable-livingston-menus	 enable Livingston-compatible menus],
	[case $enableval in
		yes) 	AC_DEFINE(USE_LIVINGSTON_MENUS,1,
                                  [Enable support for Livingstone menus]);;
		*)	;;
	esac])

AH_TEMPLATE(DENY_SHELL,
            [When defined, users with the given shell will be always denied
             access])
AC_ARG_ENABLE(deny_shell,
	[  --enable-deny-shell=STRING 	 always reject users with given shell],
	[case $enableval in
		yes|no)		AC_MSG_ERROR(--enable-deny-shell requires an argument)
				exit 1;;
		"*")		AC_DEFINE_UNQUOTED(DENY_SHELL, $enableval);;
		*)		AC_DEFINE_UNQUOTED(DENY_SHELL, "$enableval");;
	esac])

AC_ARG_ENABLE(osfc2,
	[  --enable-osfc2	         enable OSFC2 support],
	[case $enableval in
		yes)		AC_DEFINE(OSFC2,1,
                                          [Define this to enable OSFC2 support<]);;
		no)		;;
		*)		AC_MSG_ERROR(--enable-osfc2 can't be used with an argument)
				exit 1;;
	esac])

## ***********************************************************************
## *           Do some final checks and create Makefiles                 *
## ***********************************************************************

AC_SUBST(BUILD_NAS_SCM)
AC_SUBST(BUILD_PAM_RADIUS_LA)
if test x$BUILD_CLIENT = xyes; then
	AC_CHECK_LIB(pam, pam_start,
			[ BUILD_PAM_RADIUS_LA='pam_radius.la$(EXEEXT)' ],
			[ AC_MSG_WARN([-lpam not found. Won't build pam_radius.so])])
	if test x$USE_GUILE != xno; then
		BUILD_NAS_SCM=nas.scm
	else
		AC_MSG_WARN([GUILE not installed. Won't build nas.scm])
	fi
fi

if test "$EMACS" != "no"; then
	lisp_LISP='$(LISPSRC)'
fi
AC_SUBST(lisp_LISP)

AC_OUTPUT(Makefile m4/Makefile  intl/Makefile po/Makefile.in 
          include/Makefile include/snmp/Makefile
          lib/Makefile sql/Makefile snmplib/Makefile 
	  radscm/Makefile 
          radiusd/Makefile radlast/Makefile radwho/Makefile 
          raduse/Makefile radzap/Makefile 
          radscripts/Makefile doc/Makefile 
	  doc/texinfo/Makefile doc/man/Makefile doc/man/config.so 
          doc/rfc/Makefile 
          mibs/Makefile 
          po/Makefile 
          elisp/Makefile 
          raddb/Makefile 
          db/Makefile 
          client/Makefile 
          client/nas/Makefile 
          client/pam_radius/Makefile 
          radtest/Makefile
          examples/Makefile 
          test/Makefile 
          test/raddb/Makefile 
          test/proxy/Makefile 
          test/shell/Makefile
          test/dejagnu/Makefile
          test/dejagnu/lib/Makefile
          scripts/Makefile
          scripts/guile/Makefile 
          scripts/guile/1.4/Makefile 
          scripts/guile/1.6/Makefile 
          contrib/Makefile)

if test "x$USE_NOTIFY" = xyes; then
  echo "** WARNING: --enable-notify is obsolete, use ttl.scm instead. Please"
  echo "** WARNING: consult file NEWS for a description on how to do that."
fi

