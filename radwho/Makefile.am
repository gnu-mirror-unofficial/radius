# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003 Free Software Foundation, Inc.
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
bin_PROGRAMS    = radwho
radwho_SOURCES = radwho.c 
radwho_LDADD   = @LIBGNURADIUS@ @LIBINTL@
INCLUDES        = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/lib @INCLUDEPATH@
AM_CPPFLAGS=@PATHFLAGS@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out
CLEANFILES=*.ln

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radwho_SOURCES:.c=.ln)
	$(LINT.c) -u $(radwho_SOURCES:.c=.ln) -L../lib -llog -lrad -ldebug



endif

