# This file is part of GNU Radius.
# Copyright (C) 2004,2007 Free Software Foundation, Inc.
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
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

all: types.h dictionary.h 

dictionary.h: $(top_srcdir)/raddb/dict/standard
	$(AWK) -f $(top_srcdir)/scripts/dict.awk $(top_srcdir)/raddb/dict/standard > dictionary.h

types.h: $(top_builddir)/scripts/mktypes
	$(top_builddir)/scripts/mktypes > $@

SUFFIXES = .h .hin

debug.h: Makefile.in debug.hin $(top_builddir)/scripts/debugdef.m4

.hin.h:
	m4 $(top_srcdir)/scripts/debugdef.m4 $< > $@

MAINTAINERCLEANFILES = dictionary.h debug.h

pkginclude_HEADERS = \
 types.h\
 debug.h\
 dictionary.h\
 radius.h\
 argcv.h\
 envar.h\
 list.h\
 md4.h\
 md5.h\
 mem.h\
 raddbm.h\
 radpaths.h\
 radscm.h\
 radutmp.h\
 sha1.h\
 symtab.h

EXTRA_DIST=radargp.h debug.hin
DISTCLEANFILES = types.h 

