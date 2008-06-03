# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2005,2006,
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

noinst_LIBRARIES = libradextra.a
libradextra_a_SOURCES = \
 intl.c\
 radargp.c\
 readline.c 

lib_LTLIBRARIES=libgnuradius.la

NTOSTR_C = \
 inttostr.c\
 longtostr.c\
 offtostr.c\
 sizetostr.c\
 uinttostr.c\
 ulongtostr.c

libgnuradius_la_SOURCES= \
 argcv.c\
 ascend.c\
 avl.c\
 c-strcase.c\
 client.c\
 cryptpass.c\
 dbm.c\
 debug.c\
 deflog.c\
 dict.c\
 envar.c\
 getgr.c\
 gethost_r.c\
 getpw_r.c\
 insist.c\
 iputil.c\
 leakdetect.c\
 list.c\
 logger.c\
 md4.c\
 md5.c\
 md5crypt.c\
 nas.c\
 printutmp.c\
 raddb.c\
 radpaths.c\
 radpdu.c\
 radsrv.c\
 radutmp.c\
 realms.c\
 sha1.c\
 smbdes.c\
 slist.c\
 symtab.c\
 sysdep.c\
 users_gram.c\
 users_lex.c\
 util.c\
 $(NTOSTR_C)

localedir = $(datadir)/locale

VERSION_SCRIPT=$(srcdir)/gnuradius.vers
libgnuradius_la_LDFLAGS = --version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@ @VERSION_SCRIPT_OPTION@

AM_CPPFLAGS=-DLOCALEDIR=\"$(localedir)\" @PATHFLAGS@

BUILT_SOURCES=users_gram.c users_lex.c
MAINTAINERCLEANFILES=users_gram.c users_gram.h users_lex.c
MOSTLYCLEANFILES=
INCLUDES=@RADIUS_INCLUDE_PATH@ 
EXTRA_DIST=users.y users.l gnuradius.vers numtostr.c intprops.h

noinst_HEADERS=users_gram.h 

YLWRAP=$(SHELL) $(top_srcdir)/scripts/gylwrap

users_gram.c users_gram.h: $(srcdir)/users.y
	$(YLWRAP) "$(YACC)" $(srcdir)/users.y \
                  y.tab.c users_gram.c y.tab.h users_gram.h \
                  -- -yy uyy -vdt

users_lex.c: $(srcdir)/users.l
	$(YLWRAP) "$(LEX)" $(srcdir)/users.l \
		  lex.yy.c users_lex.c -- -yy uyy

users_lex.o: users_lex.c users_gram.h $(top_srcdir)/include/parser.h
users_gram.o: users_gram.c users_gram.h $(top_srcdir)/include/parser.h

