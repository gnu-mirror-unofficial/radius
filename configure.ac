# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2005 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

AC_PREREQ(2.59)

AC_REVISION($Revision$)
AC_INIT(GNU Radius, 1.3.91, bug-gnu-radius@gnu.org)
AC_CONFIG_SRCDIR(radiusd/radiusd.c)
AC_CONFIG_AUX_DIR([scripts])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(no-exeext)
AC_CONFIG_HEADERS([config.h])

AC_SUBST(BUILD_TARGET)
AC_SUBST(INCLUDEPATH)
AC_SUBST(RADIUS_PID)

AC_SUBST(RADIUS_INCLUDE_PATH)
RADIUS_INCLUDE_PATH='-I$(top_builddir) -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)/include/radius -I$(top_srcdir)/include/radius'

## * Checks for programs.
AC_PROG_CC
AM_PROG_CC_STDC
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_AWK

AC_PATH_PROG(PS, ps, no, $PATH:/usr/ccs/bin:/usr/bin:/usr/local/bin)
AC_ARG_VAR(PS,[Full path to ps binary])

AC_PROG_LN_S
AM_PROG_LIBTOOL

M4='`cd $(top_srcdir); pwd`/scripts/missing --run m4'
AC_SUBST(M4)

AC_SUBST(build_POFILTER)
RA_MAINTAINER_MODE([build_POFILTER=pofilter])

### Make sure Guile is installed.
AC_ARG_WITH(guile,
	AC_HELP_STRING([--without-guile],
	[do not compile Guile support]),
	[USE_GUILE=$withval],
	[USE_GUILE=yes])

AC_ARG_WITH(server-guile,
	AC_HELP_STRING([--with-server-guile], [compile server Guile support]),
	[USE_SERVER_GUILE=$withval],
	[USE_SERVER_GUILE=yes])

if test $USE_GUILE = yes; then
	RA_CHECK_GUILE(,
			[LIBRADSCM="libradscm.la libservscm.a"
                         RADSCM=radscm
			 RADSESSION=radsession
			 RADSCM_BUILT_SOURCES_LIST='${RADSCM_BUILT_SOURCE_FILES}'
			 RADSCM_PKGDATA='${RADSCM_PKGDATA_FILES}'
                         GUILE_BINDIR=`guile-config info bindir`
			 if test $USE_SERVER_GUILE = yes; then
				AC_DEFINE(USE_SERVER_GUILE,1,
                                    [Define this to enable Guile interface])
				RA_RADIUSD_LDADD(-L../radscm -lradscm ../radscm/libservscm.a $GUILE_LIBS)
			 fi],
                        [USE_GUILE=no])
fi

# We used to have 'case' here that determined the Guile snarfer version
# to use. Now that we don't support 1.4 any more, it is gone as well.
# Hopefully, next versions of Guile will install the snarfer, so I
# be able to get rid from scripts/guile once and for all. For the
# time being, let's assume the shipped 1.6-compatible snarfer will
# work for all future versions of Guile. If it does not, please report
# to <bug-gnu-radius@gnu.org>. Make sure to include a copy of your config.log,
# and any relevant error messages, produced when compiling/running.

GUILE_SNARF_VERSION="1.6"

AC_SUBST(GUILE_INCLUDES)
AC_SUBST(GUILE_LIBS)
AC_SUBST(GUILE_SNARF_VERSION)
AC_SUBST(GUILE_BINDIR)
AC_SUBST(LIBRADSCM)
AC_SUBST(RADSCM)
AC_SUBST(RADSESSION)
AC_SUBST(RADSCM_BUILT_SOURCES_LIST)
AC_SUBST(RADSCM_PKGDATA)

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

## *************************************
## add any additional libraries/includes
## *************************************
AC_MSG_CHECKING(for additional includes)
AC_ARG_WITH(include-path,
	AC_HELP_STRING([--with-include-path=PATH],
	[specify additional include paths. PATH is a ':' separated list of additional include paths.]),
	[ for path in `echo $withval | sed 's/:/ /g'`
          do
            INCLUDEPATH="$INCLUDEPATH -I$path"
          done])
AC_MSG_RESULT($INCLUDEPATH)

AC_MSG_CHECKING(for additional libraries)
AC_ARG_WITH(lib-path,    
	AC_HELP_STRING([--with-lib-path=PATH],
	[specify additional library paths.]),
	[ for path in `echo $withval | sed 's/:/ /g'`
          do
            LIBS="$LIBS -L$path"
          done])
AC_MSG_RESULT($LIBS)

## * Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyaddr)
AC_CHECK_LIB(crypt, crypt)

USE_LOADABLE_MODULES=no
if test "$enable_shared" = yes; then
  AC_CHECK_LIB(ltdl, lt_dlinit,[
    AC_DEFINE(HAVE_LIBLTDL,
	      1,
	      [Define to 1 if you have the `ltdl' library (-lltdl).])
    RA_RADIUSD_LDADD([-lltdl])
    USE_LOADABLE_MODULES=yes])
fi
if test $USE_LOADABLE_MODULES = yes; then
	AC_DEFINE(USE_LOADABLE_MODULES,1,
                  [Define if radiusd is able to use loadable modules])
fi

## * Checks for header files.

# Override CPPFLAGS
save_CPPFLAGS=$CPPFLAGS
CPPLAGS="$CPPLAGS $INCLUDEPATH"

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(argp.h fcntl.h malloc.h strings.h\
 sys/file.h sys/time.h sys/types.h unistd.h\
 ctype.h sys/socket.h socket.h netinet/in.h arpa/inet.h\
 netdb.h stdarg.h varargs.h termcap.h termios.h termio.h sgtty.h\
 crypt.h sys/uio.h sys/select.h sys/resources.h getopt.h libintl.h)

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_SIGNAL
AC_CHECK_SIZEOF(uint32_t)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned int)

AC_CHECK_TYPE(socklen_t, , AC_DEFINE(socklen_t, int, [Define to int if <sys/types.h> does not define]),
[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SOCKET_H
# include <socket.h>
#endif
])

AC_CHECK_MEMBERS([struct passwd.pw_expire, struct passwd.pw_change], , ,
                 [#include <pwd.h>])

## Check for shadow support
AC_CHECK_HEADER([shadow.h],
  [AC_CHECK_FUNCS(getspnam)
   AC_CHECK_TYPES(struct spwd, , ,
    [ #include <shadow.h> ])
   AC_CHECK_MEMBERS([struct spwd.sp_expire], , ,
    [ #include <shadow.h> ])],
  [AC_CHECK_HEADER([sys/security.h],
    [AC_CHECK_HEADER([prot.h],
      [AC_CHECK_TYPES(struct pr_passwd, , ,
       [ #include <sys/security.h>
         #include <prot.h> ])
       AC_CHECK_FUNCS(getprpwnam)
       AC_CHECK_MEMBERS([struct pr_passwd.uflg.fg_lock])])])])

AH_BOTTOM([
#if defined(HAVE_GETSPNAM) && defined(HAVE_STRUCT_SPWD)
# define PWD_SHADOW SHADOW
#elif defined(HAVE_STRUCT_PR_PASSWD) && defined(HAVE_GETPRPWNAM)
# define PWD_SHADOW OSFC2
#endif])

## * Check for national language support
AM_GNU_GETTEXT(no-libtool, need-ngettext)
AM_GNU_GETTEXT_VERSION(0.12.1)
if test ".$BUILD_INCLUDED_LIBINTL" = ".yes" ; then
	AC_DEFINE(WITH_INCLUDED_LIBINTL,1,
                  [Define if the included libintl is used])
	INCLUDEPATH="$INCLUDEPATH -I\$(top_srcdir)/intl"
fi

# Initialize the test suite.
AC_CONFIG_TESTDIR(tests)
AC_CONFIG_FILES([tests/Makefile
                 tests/atlocal
                 tests/raddb/Makefile
                 tests/proxy/Makefile]) 
AM_MISSING_PROG([AUTOM4TE], [autom4te])

## * Provide top and bottom parts of config.h.
AH_TOP([
#ifndef _REENTRANT
# define _REENTRANT
#endif
])

AC_ARG_VAR([LEAK_DETECTOR],
           [Enable leak detector support. Allowed values: 0 - disable leak detector, 1 - enable debug messages, 2 - enable debug messages and memory statistics. The setting takes effect only if --enable-maintainer-mode is specified. Using --enable-maintainer-mode alone implies LEAK_DETECTOR=1.])

case $LEAK_DETECTOR in
[[0-9]])	AC_DEFINE_UNQUOTED(LEAK_DETECTOR, $LEAK_DETECTOR);;
*)	;;
esac

AH_BOTTOM([
/*FIXME*/
#if defined(sun) && !defined(__EXTENSIONS__)
# define __EXTENSIONS__
#endif

#ifdef MAINTAINER_MODE
# define LEAK_DETECTOR 1
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
AC_CHECK_MEMBERS([struct sockaddr_in.sin_len], , ,
    [ #include <sys/types.h>
      #include <netinet/in.h> ])
RA_CHECK_INADDR_LOOPBACK

## * Checks for library functions.
#AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_MMAP
AC_CHECK_FUNCS(setsid gethostname gettimeofday \
 mkdir mktime select socket strdup strtol lockf \
 setlocale bzero \
 inet_ntoa inet_aton \
 setvbuf setegid setregid setresgid seteuid setreuid getdtablesize sigaction)

AC_SUBST(GNU_INCLUDES)

AC_CHECK_HEADER([obstack.h],
                [AC_FUNC_OBSTACK],
	        [AC_CONFIG_LINKS(include/radius/obstack.h:lib/obstack.h)
                 GNU_INCLUDES="$GNU_INCLUDES obstack.h"
                 AC_LIBOBJ(obstack)])


AC_CHECK_DECLS([strncasecmp, strtok_r, localtime_r, asprintf, vasprintf,
getline, crypt, crypt_set_format], , ,
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
#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#endif
#include <stdio.h>])

# Restore CPPFLAGS
CPPFLAGS=$save_CPPFLAGS

AC_ARG_WITH(included-argp,
	AC_HELP_STRING([--with-included-argp],
	[use included argp library.]),
	[USE_INCLUDED_ARGP=$withval],
	[USE_INCLUDED_ARGP=no])

AC_CHECK_FUNCS(argp_parse, :, USE_INCLUDED_ARGP=yes)
if test "$ac_cv_header_argp_h" = "no"; then
	USE_INCLUDED_ARGP=yes
fi

AC_MSG_CHECKING(whether extern program_invocation_name is declared)
AC_TRY_COMPILE([#include <argp.h>
#include <errno.h>],
[ program_invocation_name = "test"; ],
[AC_DEFINE(PROGRAM_INVOCATION_NAME_DECLARED,1,
           [Define if program_invocation_name is declared in argp.h])
 AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)])

AH_BOTTOM([
#ifndef PROGRAM_INVOCATION_NAME_DECLARED
extern char *program_invocation_short_name;
extern char *program_invocation_name;
#endif])

AC_MSG_CHECKING(whether program_invocation_name is present)
AC_TRY_COMPILE([#include <argp.h>
#include <errno.h>],
[
#ifndef PROGRAM_INVOCATION_NAME_DECLARED
	extern char *program_invocation_name;
#endif
	program_invocation_name = "test";
],
[AC_DEFINE(HAVE_PROGRAM_INVOCATION_NAME,1,
           [Define if the variable program_invocation_name exists])
 AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)
 USE_INCLUDED_ARGP=yes])


if test $USE_INCLUDED_ARGP = yes; then
        AC_DEFINE(WITH_INCLUDED_ARGP, 1,
                  [Define if we're using included argp])

        AC_CONFIG_LINKS([include/radius/getopt.h:lib/getopt.h
                         include/radius/argp.h:lib/argp.h])
        GNU_INCLUDES="$GNU_INCLUDES argp.h getopt.h"

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

AC_ARG_WITH([readline],
            AC_HELP_STRING([--without-readline],
                           [do not use readline]),
            [
case "${withval}" in
  yes) usereadline=yes ;;
  no)  usereadline=no ;;
  *)   AC_MSG_ERROR(bad value ${withval} for --without-readline) ;;
esac],[usereadline=yes])

dnl Check for GNU Readline
AC_SUBST(READLINE_LIBS)

if test x"$usereadline" = x"yes"; then

	dnl FIXME This should only link in the curses libraries if it's
	dnl really needed!
	
	dnl Check for Curses libs.
	CURSES_LIBS=
	for lib in ncurses curses termcap
	do
		AC_CHECK_LIB($lib, tputs, [CURSES_LIBS="-l$lib"; break])
	done

	saved_LIBS=$LIBS
	LIBS="$LIBS $CURSES_LIBS"
	AC_CHECK_LIB(readline, readline, ra_have_readline=yes)
	LIBS=$saved_LIBS
	
	if test x"$ra_have_readline" = x"yes"; then
		AC_CHECK_HEADERS(readline/readline.h,
			AC_DEFINE(WITH_READLINE,1,[Enable use of readline]))
			READLINE_LIBS="-lreadline $CURSES_LIBS"
			saved_LIBS=$LIBS
			LIBS="$LIBS $READLINE_LIBS"
			AC_CHECK_FUNCS(rl_completion_matches)
			LIBS=$saved_LIBS
	else
		AC_MSG_WARN(readline requested but does not seem to be installed)
	fi

fi
AH_BOTTOM([
/* Newer versions of readline have rl_completion_matches */
#ifndef HAVE_RL_COMPLETION_MATCHES
# define rl_completion_matches completion_matches
#endif])

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
	AC_HELP_STRING([--disable-debug],
	[disable debugging functions]),
	[case $enableval in
		yes)	RADIUS_DEBUG=1;;
		no)	RADIUS_DEBUG=0;;
	 esac])

AC_DEFINE_UNQUOTED(RADIUS_DEBUG, $RADIUS_DEBUG,
                   [Define to 1 to enable debugging])

AC_MSG_CHECKING(for log directory path)
AC_ARG_WITH(log-dir,
	AC_HELP_STRING([--with-log-dir=PATH],
	[Use PATH instead of default log directory path]),
	[case "x$withval" in
	 x/*) RADLOG_DIR=$withval;;
         *)  AC_MSG_ERROR(Argument must be an absolute pathname);;
         esac],
        [if test -d /var/log; then
  	    RADLOG_DIR="/var/log"
         elif test -d /usr/adm; then
            RADLOG_DIR="/usr/adm"
         else
            RADLOG_DIR="NONE"
         fi])
AC_MSG_RESULT($RADLOG_DIR)
if test $RADLOG_DIR == NONE; then
   AC_MSG_ERROR("Don't know where to place default logging directory")
fi  

AC_MSG_CHECKING(for pidfile directory path)
AC_ARG_WITH(pid-dir,
	AC_HELP_STRING([--with-pid-dir=PATH],
	[Use PATH instead of default podfile location]),
	[case "x$withval" in
	 x/*) RADPID_DIR=$withval;;
         *)  AC_MSG_ERROR(Argument must be an absolute pathname);;
         esac],
        [if test -d /var/run; then
           RADPID_DIR="/var/run"
         else
           RADPID_DIR='$(sysconfdir)/raddb'
         fi])
AC_MSG_RESULT($RADPID_DIR)

AC_SUBST(PATHFLAGS)
AC_SUBST(RADPID_DIR)
AC_SUBST(RADLOG_DIR)
PATHFLAGS='-DSYSCONFDIR=\"$(sysconfdir)\" -DRADPID_DIR=\"$(RADPID_DIR)\" -DRADLOG_DIR=\"$(RADLOG_DIR)\"'

AC_DEFINE_UNQUOTED(BUILD_TARGET,
                   "$target", [Target the package is built for])

## ***************
## server vs. client 
## ***************
AC_MSG_CHECKING(whether to build radius daemon)
AC_ARG_ENABLE(server,
	AC_HELP_STRING([--disable-server],
	[do not compile radius daemon (radiusd) and accompanying programs (implies --enable-client]),
	[case $enableval in
         yes|no) BUILD_SERVER=$enableval;;
	 *)      AC_MSG_ERROR([Invalid argument for --enable-server]);;
         esac],
	[BUILD_SERVER=yes])
AC_MSG_RESULT($BUILD_SERVER)

AC_MSG_CHECKING(whether to build client programs)
AC_ARG_ENABLE(client,
	AC_HELP_STRING([--enable-client],
	[compile client programs]),
	[case $enableval in
         yes) BUILD_CLIENT=$enableval;;
         no)  if test $BUILD_SERVER = yes; then
		AC_MSG_WARN([--disable-server implies --enable-client])
                enableval=yes
              fi
              BUILD_CLIENT=$enableval;;
         *)   AC_MSG_ERROR([Invalid argument for --enable-client]);;
         esac],
	[case $BUILD_SERVER in
         yes)	BUILD_CLIENT=no;;
	 no)    BUILD_CLIENT=yes;;
         esac])
AC_MSG_RESULT($BUILD_CLIENT)

## **************
## Contributions
## **************

AC_ARG_WITH(php,
            AC_HELP_STRING([--with-php=PATH],
                           [Enable PHP module]),
            [case $withval in
             no)	PHP_PREFIX=
			;;
             yes)       PHP_PREFIX=
			;;
             /*)	PHP_PREFIX=$withval
			;;
	     *)		AC_MSG_ERROR([Invalid prefix in --enable-php])
	     esac],
             [PHP_PREFIX=])

if test "$PHP_PREFIX" != ""; then
  AC_SUBST(PHP_INCLUDES)
  PHP_INCLUDES="-I${PHP_PREFIX}/include/php/main -I${PHP_PREFIX}/include/php/Zend -I${PHP_PREFIX}/include/php -I${PHP_PREFIX}/include/php/TSRM"

  php_save_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS $PHP_INCLUDES"
  AC_CHECK_HEADER([php.h],[:],AC_MSG_ERROR([php.h not found]))
  CPPFLAGS=$php_save_CPPFLAGS

  AC_SUBST(PHPMODDIR)
  AC_ARG_WITH([php-moddir],
              AC_HELP_STRING([--with-php-moddir=PATH],
                             [Set install prefix for PHP extension modules]),
              [case $withval in
               /*)	PHPMODDIR=$withval;;
	       *)	AC_MSG_ERROR([--with-php-moddir requires absolute file name as its argument]);;
	       esac],
               [PHPMODDIR='$(libdir)/php/extensions'])

  AC_SUBST(BUILD_MOD_RADIUS_LA)
  BUILD_MOD_RADIUS_LA=mod_radius.la
fi

## **************
## auth port no
## **************
AC_MSG_CHECKING(authentication port number)
AC_ARG_WITH(auth-port,
	AC_HELP_STRING([--with-auth-port={rfc|old|NUMBER}],
	[specify port number to use for authentication]),
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
	AUTH_PORT=1812)
ACCT_PORT="`expr $AUTH_PORT + 1`"
AC_MSG_RESULT([Default ports are $AUTH_PORT/$ACCT_PORT])
AC_SUBST(AUTH_PORT)
AC_SUBST(ACCT_PORT)
AC_DEFINE_UNQUOTED(DEF_AUTH_PORT, $AUTH_PORT, [Default authentication port])
AC_DEFINE_UNQUOTED(DEF_ACCT_PORT, $ACCT_PORT, [Default accounting port])
		
## **************
## PAM support
## **************
AC_ARG_ENABLE(pam,
	AC_HELP_STRING([--enable-pam],
	[enable pam support]),
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
		[AC_MSG_FAILURE([The requested library libpam is not found or is unusable])])
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
		 [AC_MSG_FAILURE([The requested library libdbm is not found or is unusable])])) 
}

rad_lib_ndbm() {
	AC_CHECK_HEADER(ndbm.h,,
			[ AC_MSG_ERROR(can't find header ndbm.h)
			exit 0] )
	AC_CHECK_FUNC(dbm_open,, 					
		AC_CHECK_LIB(ndbm, dbm_open,
			[ AC_DEFINE(HAVE_LIBNDBM) 
			  RA_RADIUSD_LDADD(-lndbm) ],
		[AC_MSG_FAILURE([The requested library libndbm is not found or is unusable])]))
}

AH_TEMPLATE(USE_DBM,[Define this to enable DBM support])
AC_ARG_ENABLE(dbm,
	AC_HELP_STRING([--enable-dbm[={dbm|ndbm}]],
	[include dbm support]),
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

SQL_MODULES=
AC_SUBST(SQL_MODULES)

SQL_LIBOBJS=
AC_SUBST(SQL_LIBOBJS)

SQL_LTLIBOBJS=
AC_SUBST(SQL_LTLIBOBJS)

BUILD_SQL=
AC_SUBST(BUILD_SQL)
AC_SUBST(SQLLIB)

SQL_LOADABLE_MODULES=
AC_SUBST(SQL_LOADABLE_MODULES)

AH_TEMPLATE(USE_SQL,[Enables SQL support])

AC_DEFUN([RA_SQL_LDADD],[
     if test $USE_LOADABLE_MODULES = yes; then
	$1=$2
     else	
        RA_RADIUSD_LDADD($2)
     fi 			
])


## *********
## MySQL
## *********
AH_TEMPLATE(USE_SQL_MYSQL,[When defined, enable MySQL support])
AH_TEMPLATE(HAVE_LIBMYSQL,[Define if you have libmysql])
AC_SUBST(MYSQLLIBS)

mysql_init() {
	RA_CHECK_LIB(mysqlclient, 
	                     mysql_real_connect, 
	                    [-lm],
                            [ AC_DEFINE(USE_SQL_MYSQL)
                              AC_DEFINE(HAVE_LIBMYSQL)
			      RA_SQL_LDADD(MYSQLLIBS, $ra_cv_lib_mysqlclient)
                            ],
			    [AC_MSG_FAILURE([The requested library libmysqlclient is not found or is unusable])],
                            [/usr/local/lib/mysql /usr/lib/mysql])
}

AC_ARG_WITH(mysql,
	AC_HELP_STRING([--with-mysql],
	[Configure to work with MySQL]),
	[case $withval in
	 yes)   SQL_MODULES="$SQL_MODULES mysql"
		;;
	 no)    ;;
        esac])


# *********
# Postgres
# *********
AH_TEMPLATE(USE_SQL_POSTGRES,[When defined, enable PostgreSQL support])
AH_TEMPLATE(HAVE_LIBPQ,[Define if you have libpq]) 
AC_SUBST(POSTGRESLIBS)

postgres_init() {
	RA_CHECK_LIB(pq, PQconnectStart, [],
			    [ AC_DEFINE(USE_SQL_POSTGRES)
                              AC_DEFINE(HAVE_LIBPQ)
			      RA_SQL_LDADD(POSTGRESLIBS, $ra_cv_lib_pq)],
		            [AC_MSG_FAILURE([The requested library libpq is not found or is unusable])],
                            [/usr/local/pgsql/lib /usr/pgsql/lib])
}

AC_ARG_WITH(postgres,
	AC_HELP_STRING([--with-postgres],
	[Configure to work with Postgres]),
	[case $withval in
	 yes)	SQL_MODULES="$SQL_MODULES postgres"
		;;
	 no)    ;;
        esac])


## *********
## ODBC
## *********
AH_TEMPLATE(USE_SQL_ODBC,[When defined, enable ODBC support])
AH_TEMPLATE(HAVE_LIBODBC,[Define if you have libodbc or libiodbc]) 
AC_SUBST(ODBCLIBS)

rad_lib_odbc() {
	RA_CHECK_LIB(odbc, SQLAllocHandle, [],
			    [ AC_DEFINE(USE_SQL_ODBC)
                              AC_DEFINE(HAVE_LIBODBC)
			      RA_SQL_LDADD(ODBCLIBS, $ra_cv_lib_odbc)],
                            [AC_MSG_FAILURE([The requested library libobdc is not found or is unusable])],
                            [/usr/local/lib])
}

rad_lib_iodbc() {
	RA_CHECK_LIB(iodbc, SQLAllocHandle, [],
			    [ AC_DEFINE(USE_SQL_ODBC)
                              AC_DEFINE(HAVE_LIBODBC)
		              RA_SQL_LDADD(ODBCLIBS, $ra_cv_lib_iodbc)],
		            [AC_MSG_FAILURE([The requested library libiodbc is not found or is unusable])],
                            [/usr/local/lib])
}

with_flag_used=odbc

odbc_init() {
         case $with_flag_used in
	 yes|odbc|ODBC)
		rad_lib_odbc
		;;
	 iodbc|iODBC|IODBC)
		rad_lib_iodbc
		;;
	 no)	;;
	 esac
}

AC_ARG_WITH(odbc,
	AC_HELP_STRING([--with-odbc[={odbc|iodbc}]],
	[Configure to work with ODBC]),
	[case $withval in
	 yes|odbc|ODBC|iodbc|iODBC|IODBC)
		SQL_MODULES="$SQL_MODULES odbc"
		with_flag_used=$withval
		;;
	 no)    with_flag_used=$withval
		;;
	 *)	AC_MSG_ERROR(unsupported option value: $withval)
        esac])


## ***********
## General SQL support
## ***********

AC_ARG_WITH(sql,
        AC_HELP_STRING([--with-sql=modlist],
                       [Configure to work with SQL]),
	[for mod in `echo $withval | tr ':,' '  '`
         do
		if test -r $srcdir/sql/${mod}.c; then
			SQL_MODULES="$SQL_MODULES ${mod}"
		else
			AC_MSG_ERROR(No such SQL module: $mod)
		fi
	 done])

dummy_init() {
	:
}

if test -n "$SQL_MODULES"; then
	USE_SQL=1
        AC_DEFINE(USE_SQL)
	BUILD_SQL=libsql.la
	SQLLIB=../sql/libsql.la

	for module in $SQL_MODULES
	do
		${module:-dummy}_init
		if test $USE_LOADABLE_MODULES = yes; then
		   SQL_LOADABLE_MODULES="$SQL_LOADABLE_MODULES ${module}.la"
		else
		   SQL_LIBOBJS="$SQL_LIBOBJS ${module}.o"
	        fi
	done
	S=`echo "$SQL_LIBOBJS" |
                  sed 's,\.[[^.]]* ,$U&,g;s,\.[[^.]]*$,$U&,'`
	SQL_LTLIBOBJS=`echo "$S" |
                  sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`

	AC_CONFIG_COMMANDS([sql/modlist.h],
                           [$srcdir/scripts/sqlmod.sh $SQL_MODULES > sql/modlist.h],
                           [if test $USE_LOADABLE_MODULES = yes; then
				SQL_MODULES=
                            else
                                SQL_MODULES="$SQL_MODULES"
                            fi])
fi

## **************
## SNMP
## **************

AH_TEMPLATE(USE_SNMP, [Define this to enable SNMP support])
AC_SUBST(SNMP_CONFIG)
SNMP_CONFIG="# "
AC_ARG_ENABLE(snmp,
	AC_HELP_STRING([--enable-snmp[={yes|no|compat}]],
	[enable SNMP support]),
	[case $enableval in
		compat)		USE_SNMP=yes
				AC_DEFINE(USE_SNMP)
				AC_DEFINE(SNMP_COMPAT_0_96,1,
                   [Enable support for MIBS used in 0.96 branch])
				SNMP_CONFIG=""
				;;
		yes)		USE_SNMP=yes
				AC_DEFINE(USE_SNMP)
				SNMP_CONFIG=""
				;;
		no)		;;
		*)		AC_MSG_ERROR(--enable-snmp can't be used with an argument)				
				exit 1;;
	esac])

AH_BOTTOM([
#ifndef HAVE_MMAP
# undef USE_SNMP
#endif])

## **************
## Directories
## **************
PAMDIR='$(prefix)/lib/security'
AC_ARG_WITH(pamdir,
	AC_HELP_STRING([--with-pamdir=DIR],
	[install PAM modules in DIR [[PREFIX/lib/security)]]]),
	[PAMDIR=$withval])
AC_SUBST(PAMDIR)

## ***********************************************************************
## *          Compatibility options and some special hacks               *
## ***********************************************************************

AC_ARG_ENABLE(livingston-menus,
	AC_HELP_STRING([--enable-livingston-menus],
	[enable Livingston-compatible menus]),
	[case $enableval in
		yes) 	AC_DEFINE(USE_LIVINGSTON_MENUS,1,
                                  [Enable support for Livingstone menus]);;
		*)	;;
	esac])

AH_TEMPLATE(DENY_SHELL,
            [When defined, users with the given shell will be always denied
             access])
AC_ARG_ENABLE(deny_shell,
	AC_HELP_STRING([--enable-deny-shell=STRING],
	[always reject users with given shell]),
	[case $enableval in
		yes|no)		AC_MSG_ERROR(--enable-deny-shell requires an argument)
				exit 1;;
		"*")		AC_DEFINE_UNQUOTED(DENY_SHELL, $enableval);;
		*)		AC_DEFINE_UNQUOTED(DENY_SHELL, "$enableval");;
	esac])

## ***********************************************************************
## *           Do some final checks and create Makefiles                 *
## ***********************************************************************

AC_SUBST(BUILD_NAS_SCM)
AC_SUBST(BUILD_PAM_RADIUS_LA)

AC_SUBST(RADIUS_DAEMON)
if test x$BUILD_SERVER = xyes; then
	RADIUS_DAEMON=radiusd
fi

if test x$BUILD_CLIENT = xyes; then
	AC_CHECK_LIB(pam, pam_start,
			[ BUILD_PAM_RADIUS_LA='pam_radius.la$(EXEEXT)' ],
			[ AC_MSG_WARN([-lpam not found. Won't build pam_radius.so])])
	if test x$USE_GUILE != xno; then
		BUILD_NAS_SCM=nas.scm
	else
		AC_MSG_WARN([Guile not installed. Won't build nas.scm])
	fi
fi

if test "$EMACS" != "no"; then
	lisp_LISP='$(LISPSRC)'
fi
AC_SUBST(lisp_LISP)

dnl Define ARG_UNUSED macro
dnl
AH_BOTTOM([
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(x)
#endif

#ifndef ARG_UNUSED
# define ARG_UNUSED __attribute__ ((__unused__))
#endif

#define LOCK_DECLARE(name)
#define LOCK_SET(name)
#define LOCK_RELEASE(name)
])

AC_SUBST(LIBGNURADIUS)
LIBGNURADIUS='${top_builddir}/lib/libgnuradius.la'

RADIUS_INCLUDE_PATH="$RADIUS_INCLUDE_PATH $INCLUDEPATH"

AC_CONFIG_FILES(Makefile 
          intl/Makefile 
          po/Makefile.in
          raddb/client.conf
          raddb/config
          include/Makefile
	  include/radius/Makefile
          include/snmp/Makefile
          lib/Makefile
          sql/Makefile
          snmplib/Makefile 
	  radscm/Makefile 
          radiusd/Makefile 
          radlast/Makefile 
          radwho/Makefile 
          radzap/Makefile
          radscripts/Makefile 
          doc/Makefile 
	  doc/texinfo/Makefile
	  doc/man/Makefile 
	  doc/man/config.so 
          doc/rfc/Makefile 
          mibs/Makefile 
          elisp/Makefile 
          raddb/Makefile 
          db/Makefile 
          client/Makefile 
          client/nas/Makefile 
          client/pam_radius/Makefile 
          radtest/Makefile
          examples/Makefile 
          scripts/Makefile
          scripts/guile/Makefile 
          scripts/guile/1.6/Makefile 
          contrib/Makefile
          contrib/web-radact/Makefile
          contrib/passcvt/Makefile
          contrib/passwd_to_db/Makefile
          contrib/radsend/Makefile
          contrib/php/Makefile)
AC_OUTPUT

# EOF
