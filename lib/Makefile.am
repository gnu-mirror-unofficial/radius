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

noinst_LIBRARIES = libradextra.a
libradextra_a_SOURCES = readline.c 
libradextra_a_LIBADD = @LIBOBJS@

lib_LTLIBRARIES=libgnuradius.la
libgnuradius_la_SOURCES= \
argcv.c \
ascend.c \
avl.c \
client.c \
cryptpass.c \
dbm.c \
debug.c \
dict.c \
envar.c \
getgr.c\
gethost_r.c\
getpw_r.c\
insist.c \
intl.c \
iputil.c \
leakdetect.c \
list.c \
logger.c \
md4.c \
md5.c \
md5crypt.c \
nas.c \
printutmp.c \
radargp.c \
raddb.c \
radpaths.c \
radpdu.c \
radsrv.c \
radutmp.c \
realms.c \
sha1.c \
smbdes.c \
symtab.c \
sysdep.c \
users_gram.c \
users_lex.c \
util.c

localedir = $(datadir)/locale

libgnuradius_la_LIBADD = @LTLIBOBJS@
libgnuradius_la_LDFLAGS = --version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@ -Wl,--version-script=$(srcdir)/gnuradius.vers

AM_CPPFLAGS=-DLOCALEDIR=\"$(localedir)\" @PATHFLAGS@

BUILT_SOURCES=users_gram.c users_lex.c
MAINTAINERCLEANFILES=users_gram.c users_gram.h users_lex.c
INCLUDES=@RADIUS_INCLUDE_PATH@ 
EXTRA_DIST=users.y users.l strncasecmp.c strerror.c \
           obstack.c obstack.h rx.c \
	   getline.c getopt.c getopt1.c getopt.h \
	   vasprintf.c snprintf.c strcspn.c strtok_r.c localtime_r.c \
           argp-ba.c argp-eexst.c argp-fmtstream.c argp-fs-xinl.c \
           argp-help.c argp-parse.c argp-pv.c argp-pvh.c argp-xinl.c pin.c \
           strchrnul.c strndup.c strnlen.c gnuradius.vers

noinst_HEADERS=users_gram.h rx.h regexp.h getopt.h snprintf.h \
               argp-fmtstream.h argp-namefrob.h argp.h

YLWRAP=$(SHELL) $(top_srcdir)/scripts/ylwrap

users_gram.c users_gram.h: $(srcdir)/users.y
	$(YLWRAP) "$(YACC)" $(srcdir)/users.y \
                  y.tab.c users_gram.c y.tab.h users_gram.h \
                  -- -yy uyy -vdt

users_lex.c: $(srcdir)/users.l
	$(YLWRAP) "$(LEX)" $(srcdir)/users.l \
		  lex.yy.c users_lex.c -- -yy uyy

users_lex.o: users_lex.c users_gram.h $(top_srcdir)/include/parser.h
users_gram.o: users_gram.c users_gram.h $(top_srcdir)/include/parser.h

