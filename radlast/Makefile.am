# $Id$
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

bin_PROGRAMS    = radlast
radlast_SOURCES = radlast.c 
radlast_LDADD   = ../radlib/liblog.la ../radlib/librad.la ../radlib/libdebug.la
INCLUDES = -I$(top_srcdir)/include @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radlast_SOURCES:.c=.ln)
	$(LINT.c) -u $(radlast_SOURCES:.c=.ln) $(radlast_LDADD)

endif

