# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

bin_PROGRAMS    = raduse
raduse_SOURCES = raduse.c session.c stat.c raduse.h
raduse_LDADD   = ../snmplib/libradsnmp.a ../lib/liblog.la ../lib/librad.la ../lib/libdebug.la @LIBINTL@
INCLUDES        = -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/include/snmp @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(raduse_SOURCES:.c=.ln)
	$(LINT.c) -u $(raduse_SOURCES:.c=.ln) $(raduse_LDADD)


endif
