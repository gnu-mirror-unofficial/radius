# This file is part of GNU Radius.
# Copyright (C) 2004 Free Software Foundation, Inc.
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
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

all: types.h dictionary.h 

dictionary.h: $(top_srcdir)/raddb/dict/standard
	$(AWK) -f $(top_srcdir)/scripts/dict.awk $(top_srcdir)/raddb/dict/standard > dictionary.h

types.h: $(top_builddir)/scripts/mktypes
	$(top_builddir)/scripts/mktypes > $@

MAINTAINERCLEANFILES = dictionary.h

pkginclude_HEADERS = \
 types.h\
 dictionary.h\
 radius.h\
 argcv.h\
 envar.h\
 list.h\
 md5.h\
 mem.h\
 radargp.h\
 raddbm.h\
 radpaths.h\
 radscm.h\
 radutmp.h\
 symtab.h\
 @GNU_INCLUDES@

EXTRA_HEADERS=
DISTCLEANFILES = types.h getopt.h argp.h obstack.h

