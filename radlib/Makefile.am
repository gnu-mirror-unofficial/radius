# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

noinst_LTLIBRARIES=librad.la liblog.la libdebug.la 
librad_la_SOURCES= \
alloc.c \
argcv.c \
avl.c \
client.c \
dbm.c \
debug.c \
dict.c \
insist.c \
intl.c \
iputil.c \
leakdetect.c \
md5.c \
md5crypt.c \
mem.c \
nas.c \
raddb.c \
radpaths.c \
radutmp.c \
slist.c \
symtab.c \
sysdep.c \
users_gram.c \
users_lex.c \
util.c

LIBADD=@LIBOBJS@
librad_la_LIBADD = $(LIBADD:.o=.lo)
liblog_la_SOURCES=log.c 
libdebug_la_SOURCES=debugmod.c
LDFLAGS=-all-static
AM_CFLAGS=-static

BUILT_SOURCES=users_gram.c users_lex.c
noinst_HEADERS=users_gram.h 
MAINTAINERCLEANFILES=users_gram.c users_gram.h users_lex.c
INCLUDES= -I$(top_srcdir)/include @INCLUDEPATH@
EXTRA_DIST=users.y users.l strncasecmp.c strerror.c \
           obstack.c obstack.h rx.c \
	   getopt.c getopt1.c getopt.h \
	   vasprintf.c snprintf.c strcspn.c
noinst_HEADERS=rx.h regex.h regexp.h getopt.h snprintf.h

YLWRAP=$(SHELL) $(top_srcdir)/ylwrap

users_gram.c users_gram.h: $(srcdir)/users.y
	$(YLWRAP) "$(YACC)" $(srcdir)/users.y \
                  y.tab.c users_gram.c y.tab.h users_gram.h \
                  -- -yy uyy -vd @YACC_OPTS@ 

users_lex.c: $(srcdir)/users.l
	$(YLWRAP) "$(LEX)" $(srcdir)/users.l \
		  lex.yy.c users_lex.c -- -yy uyy

users_lex.o: users_lex.c users_gram.h $(top_srcdir)/include/parser.h
users_gram.o: users_gram.c users_gram.h $(top_srcdir)/include/parser.h

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CLEANFILES=*.ln
LINTFLAGS=-gzra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-llog.ln: $(liblog_a_SOURCES:.c=.ln)
	$(LINT.c) -Clog $(liblog_a_SOURCES:.c=.ln)

llib-lrad.ln: $(librad_a_SOURCES:.c=.ln)  llib-llog.ln
	$(LINT.c) -Crad $(librad_a_SOURCES:.c=.ln) -L. -llog

llib-ldebug.ln: $(libdebug_a_SOURCES:.c=.ln) llib-llog.ln
	$(LINT.c) -Cdebug $(libdebug_a_SOURCES:.c=.ln) -L. -llog

lint:: llib-llog.ln llib-lrad.ln llib-ldebug.ln llib-lsql.ln

LIBSRC=leakdetect.c mem.c $(libsql_a_SOURCES)

LIBLIST:; @echo $(LIBSRC) > .list
endif
