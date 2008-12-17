# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2005,
# 2007,2008 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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

AC_PREREQ(2.61)

AC_REVISION($Revision$)
AC_INIT([GNU Radius], [1.6.1], [bug-gnu-radius@gnu.org])
AC_CONFIG_SRCDIR(radiusd/radiusd.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([gnu])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(no-exeext)
AC_CONFIG_HEADERS([config.h])

AC_SUBST(BUILD_TARGET)
AC_SUBST(RADIUS_PID)

AC_SUBST(RADIUS_INCLUDE_PATH,
         ['-I$(top_builddir) -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)/include/radius -I$(top_srcdir)/include/radius -I$(top_srcdir)/lib -I$(top_srcdir)/gnu -I$(top_builddir)/gnu'])

dnl Library versioning
AC_SUBST(VI_CURRENT, 1)
AC_SUBST(VI_REVISION, 0)
AC_SUBST(VI_AGE, 0)

## * Checks for programs.
AC_PROG_CC
gl_EARLY
AM_PROG_CC_STDC
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_AWK

AC_PATH_PROG(PS, ps, no, $PATH:/usr/ccs/bin:/usr/bin:/usr/local/bin)
AC_ARG_VAR(PS,[Full path to ps binary])

AC_PROG_LN_S
AM_PROG_LIBTOOL

AC_SUBST(M4,['`cd $(top_srcdir); pwd`/build-aux/missing --run m4'])
RA_MAINTAINER_MODE
RA_LD_VERSIONING

### Check if Guile is installed.
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
				RA_RADIUSD_LDADD(../radscm/libradscm.la ../radscm/libservscm.a $GUILE_LIBS)
			 fi],
                        [USE_GUILE=no])
fi

AC_SUBST(GUILE_CONFIG, ["# "])
if test "$USE_GUILE" = yes; then
  GUILE_CONFIG=
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
## For backward compatibility, support --with-include-path ...
if test "${with_include_path+set}" = set; then
  for path in `echo $with_include_path | sed 's/:/ /g'`
  do
    CPPFLAGS="$CPPFLAGS -I$path"
  done
fi
## ... and --with-lib-path, but do not promote them.
if test "${with_lib_path+set}" = set; then
  for path in `echo $with_lib_path | sed 's/:/ /g'`
  do
    LIBS="$LIBS -L$path"
  done
fi


## * Checks for libraries.
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyaddr, nsl)
AC_SEARCH_LIBS(crypt, crypt)

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

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h malloc.h strings.h\
 sys/file.h sys/time.h sys/types.h unistd.h\
 ctype.h sys/socket.h socket.h netinet/in.h arpa/inet.h\
 netdb.h stdarg.h varargs.h termcap.h termios.h termio.h sgtty.h\
 crypt.h sys/uio.h sys/select.h sys/resources.h libintl.h)

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

gl_INIT

# Radius uses code that conflicts with gcc understanding of C aliasing:
#
#   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=38527
#
# In particular, when compiling radiusd/rewrite.y gcc >= 4.3.0 generates
# code containing explicit dead loops. According to gcc folks, such code
# generation is correct. I can hardly agree with that. And not only me.
# Quoting Linus Torvalds:
#   The gcc people are more interested in trying to find out what can be
#   allowed by the c99 specs than about making things actually _work_. The
#   aliasing code in particular is not even worth enabling, it's just not
#   possible to sanely tell gcc when some things can alias.
# (see http://lkml.org/lkml/2003/2/26/158, for details)
#
# (The code below is borrowed from Python's configure.in)
AC_SUBST(OPTFLAGS)
case $GCC in
yes)
    AC_MSG_CHECKING(whether $CC accepts -fno-strict-aliasing)
     ac_save_cc="$CC"
     CC="$CC -fno-strict-aliasing"
     AC_TRY_RUN([int main() { return 0; }],
     ac_cv_no_strict_aliasing_ok=yes,
     ac_cv_no_strict_aliasing_ok=no,
     ac_cv_no_strict_aliasing_ok=no)
     CC="$ac_save_cc"
    AC_MSG_RESULT($ac_cv_no_strict_aliasing_ok)
    if test $ac_cv_no_strict_aliasing_ok = yes
    then
      OPTFLAGS="$OPTFLAGS -fno-strict-aliasing"
    fi
    ;;
*)  # FIXME
    ;;
esac

## * Check for national language support
AM_GNU_GETTEXT([external], [need-ngettext])
AM_GNU_GETTEXT_VERSION(0.15)

AC_CHECK_FUNCS(setsid gethostname gettimeofday \
 mkdir mktime select socket strdup strtol lockf \
 setlocale bzero \
 inet_ntoa inet_aton \
 setvbuf setegid setregid setresgid seteuid setreuid getdtablesize sigaction)

# FIXME: Do we need to check for the functions before `crypt'?
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

# Always use included argp stuff.
# Earlier, configure preferred to use the one from glibc, if provided,
# while offering --with-included-argp configuration option. This proved
# to be unreliable, since there are too many broken argp implementations
# around

AH_BOTTOM([
#define GNULIB_ARGP_EXTERN_BASENAME 1
])

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

if test "$usereadline" = "yes"; then

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
	
	if test "$ra_have_readline" = "yes"; then
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
	[case "$withval" in
	 /*) RADLOG_DIR=$withval;;
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
if test $RADLOG_DIR = NONE; then
   AC_MSG_ERROR("Don't know where to place default logging directory")
fi  

AC_MSG_CHECKING(for pidfile directory path)
AC_ARG_WITH(pid-dir,
	AC_HELP_STRING([--with-pid-dir=PATH],
	[Use PATH instead of default podfile location]),
	[case "$withval" in
	 /*) RADPID_DIR=$withval;;
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

## ******************
## server vs. client 
## ******************
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
	     *)		AC_MSG_ERROR([Invalid prefix in --with-php])
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

AC_SUBST(APACHEMODDIR)
AC_SUBST(APACHE_INCLUDES)
AC_SUBST(BUILD_MOD_AUTH_RADIUS_LA)
AC_ARG_WITH(apache,
            AC_HELP_STRING([--with-apache],
                           [Enable Apache modules]),
            [case $withval in
             no)  ;;	
	     yes) AC_ARG_VAR([APXS],[Name of apxs program])
                  AC_CHECK_PROG(APXS, [apxs], [apxs], [no])
                  if test $APXS = no; then
                    AC_MSG_ERROR([apxs not found])
                  fi
                  APACHEMODDIR=`$APXS -q LIBEXECDIR`
	          APACHE_INCLUDES=`$APXS -q INCLUDEDIR`
	          BUILD_MOD_AUTH_RADIUS_LA='mod_auth_radius.la'
	          ;;
	     *)	  AC_MSG_ERROR([Invalid option argument in --with-apache])
	     esac])


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
	 yes)	USE_PAM=yes
                AC_DEFINE(USE_PAM,1,[Enable PAM support]);;
 	 no)    ;;
	 *)	AC_MSG_ERROR([--enable-pam can't be used with an argument])
		exit 1;;
	esac])
if test "$USE_PAM" = yes; then
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

	 DBM|dbm)   rad_lib_dbm
                    AC_DEFINE_UNQUOTED(USE_DBM,DBM_DBM);;

	 NDBM|ndbm) rad_lib_ndbm
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
	 compat) USE_SNMP=yes
		 AC_DEFINE(USE_SNMP)
		 AC_DEFINE(SNMP_COMPAT_0_96,1,
                           [Enable support for MIBS used in 0.96 branch])
		 SNMP_CONFIG=""
	  	 ;;
	 yes)	 USE_SNMP=yes
		 AC_DEFINE(USE_SNMP)
		 SNMP_CONFIG=""
		 ;;
         no)	 ;;
	 *)	 AC_MSG_ERROR(--enable-snmp can't be used with an argument)
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
	[USE_LIVINGSTON_MENUS=$enableval
         case $enableval in
	 yes)    AC_DEFINE(USE_LIVINGSTON_MENUS,1,
                           [Enable support for Livingstone menus]);;
	 *)	;;
	 esac])

AH_TEMPLATE(DENY_SHELL,
            [When defined, users with the given shell will be always denied
             access])
AC_ARG_ENABLE(deny_shell,
	AC_HELP_STRING([--enable-deny-shell=STRING],
	[always reject users with given shell]),
	[USE_DENY_SHELL=$enableval
         case $enableval in
         yes|no)  AC_MSG_ERROR([--enable-deny-shell requires an argument])
		  exit 1;;
	 *)	  AC_DEFINE_UNQUOTED(DENY_SHELL, "$enableval");;
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

AC_SUBST(LIBGNURADIUS,'${top_builddir}/lib/libgnuradius.la')
AC_SUBST(LIBRADEXTRA,'${top_builddir}/lib/libradextra.a ${top_builddir}/gnu/libgnu.la')

### Display the status

AC_CONFIG_COMMANDS([status],[
cat <<EOF

*******************************************************************
GNU Radius configured with the following settings:

General

NLS .............................. $status_nls
Debug ............................ $status_debug
Build Server (radiusd) ........... $status_server
Build client ..................... $status_client
Guile ............................ $status_guile
Readline ......................... $status_readline

EOF

if test "$status_server" = yes; then
cat <<EOF
Server

Authentication port .............. $status_auth_port
Accounting port .................. $status_acct_port
Log directory .................... $status_logdir
PID directory .................... $status_piddir
PAM .............................. $status_pam
DBM .............................. $status_dbm
SNMP ............................. $status_snmp
Livingston Menus ................. $status_menus
Deny Shell ....................... $status_deny_shell
Guile ............................ $status_server_guile
SQL .............................. $status_sql_modules

EOF
fi

cat <<EOF
Modules

PHP .............................. $status_mod_php
Apache ........................... $status_mod_apache
*******************************************************************
EOF
],
[status_nls=$USE_NLS
if test $RADIUS_DEBUG -eq 1; then
  status_debug=yes
else
  status_debug=no
fi
status_server="$BUILD_SERVER"
status_client="$BUILD_CLIENT"
status_guile="${USE_GUILE:-no}"
status_readline="$usereadline"
status_lispdir="${lispdir:-none}"
status_auth_port="$AUTH_PORT"
status_acct_port="$ACCT_PORT"
status_logdir="$RADLOG_DIR"
status_piddir="$RADPID_DIR"
status_pam="${USE_PAM:-no}"
status_dbm="${USE_DBM:-no}"
status_snmp="$USE_SNMP"
status_menus="$USE_LIVINGSTON_MENUS"
status_deny_shell="${USE_DENY_SHELL:-no}"
status_server_guile="$USE_SERVER_GUILE"
status_sql_modules="${SQL_MODULES:-no}"
if test "$PHP_PREFIX" != ""; then
  status_mod_php=yes
else
  status_mod_php=no
fi
if test "$BUILD_MOD_AUTH_RADIUS_LA" != ""; then
  status_mod_apache=yes
else
  status_mod_apache=no
fi
])

AC_CONFIG_FILES(Makefile 
          po/Makefile.in
          raddb/client.conf
          raddb/config
          include/Makefile
	  include/radius/Makefile
          include/snmp/Makefile
          gnu/Makefile
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
