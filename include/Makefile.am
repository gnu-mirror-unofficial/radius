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

if MAINTAINER_MODE

all: raddict.h radmibs.h

raddict.h: $(top_srcdir)/raddb/dictionary
	$(AWK) -f $(top_srcdir)/scripts/dict.awk $(top_srcdir)/raddb/dictionary > raddict.h

radmibs.h: $(top_srcdir)/mibs/radmibs.h.in
	$(AWK) -f $(top_srcdir)/scripts/mksnmp-h.awk $(top_srcdir)/mibs/radmibs.h.in > radmibs.h

lint:;

endif

MAINTAINERCLEANFILES = raddict.h radmibs.h debugmod.h

SUBDIRS=snmp

EXTRA_DIST = \
argcv.h \
debugmod.h \
cfg.h \
checkrad.h \
envar.h \
md5.h \
mem.h \
obstack1.h \
parser.h \
radargp.h \
raddbm.h \
raddict.h \
radius.h \
radiusd.h \
radlast.h \
radmibs.h \
radpaths.h \
radscm.h \
radsnmp.h \
radsql.h \
radutmp.h \
regex1.h \
rewrite.h \
slist.h \
symtab.h \
sysdep.h \
timestr.h 
