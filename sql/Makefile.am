# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2004 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

noinst_LTLIBRARIES=@BUILD_SQL@
EXTRA_LTLIBRARIES=libsql.la

INCLUDES= -I$(top_srcdir)/include -I$(top_builddir)/include @INCLUDEPATH@
libsql_la_SOURCES=disp.c mysql.c postgres.c odbc.c

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CLEANFILES=*.ln
LINTFLAGS=-gzra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-lsql.ln: $(libsql_la_SOURCES:.c=.ln)
	$(LINT.c) -Csql $(libsql_la_SOURCES:.c=.ln) -L../lib -llog -lrad

lint:: llib-lsql.ln

endif
