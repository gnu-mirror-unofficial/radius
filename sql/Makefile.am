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
EXTRA_LTLIBRARIES=libsql.la mysql.la postgres.la odbc.la
EXTRA_DIST=\
 mysql.c\
 postgres.c\
 odbc.c 
DISTCLEANFILES = modlist.h

INCLUDES=@RADIUS_INCLUDE_PATH@
libsql_la_SOURCES=disp.c
libsql_la_LIBADD=@SQL_LTLIBOBJS@

libsql_la_DEPENDENCIES = @SQL_LTLIBOBJS@

moddir = $(pkglibdir)/$(VERSION)/modules
mod_LTLIBRARIES = @SQL_LOADABLE_MODULES@

MODFLAGS=-module -avoid-version -no-undefined -rpath $(moddir) -Wl,-Bsymbolic

mysql_la_SOURCES = mysql.c
mysql_la_LIBADD = ../lib/libgnuradius.la @MYSQLLIBS@
mysql_la_LDFLAGS = $(MODFLAGS)

postgres_la_SOURCES = postgres.c
postgres_la_LIBADD = ../lib/libgnuradius.la @POSTGRESLIBS@
postgres_la_LDFLAGS = $(MODFLAGS)

odbc_la_SOURCES = odbc.c
odbc_la_LIBADD = ../lib/libgnuradius.la @ODBCLIBS@
odbc_la_LDFLAGS = $(MODFLAGS)

