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

noinst_LTLIBRARIES=@BUILD_SQL@
EXTRA_LTLIBRARIES=libsql.la

INCLUDES= -I$(top_srcdir)/include @INCLUDEPATH@
libsql_la_SOURCES=disp.c mysql.c postgres.c

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CLEANFILES=*.ln
LINTFLAGS=-gzra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-lsql.ln: $(libsql_la_SOURCES:.c=.ln) llib-llog.ln llib-lrad.ln
	$(LINT.c) -Csql $(libsql_la_SOURCES:.c=.ln) -L. -llog -lrad

lint:: llib-lsql.ln

LIBLIST:; @echo $(libsql_la_SOURCES) > .list
endif
