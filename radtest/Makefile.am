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

bin_PROGRAMS    = radtest
radtest_SOURCES = main.c gram.y input.l debugmod.c radtest.h
radtest_LDADD   = ../lib/liblog.la ../lib/librad.la @LIBINTL@
noinst_HEADERS  = gram.h
INCLUDES        = -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(srcdir) @INCLUDEPATH@
AM_YFLAGS = -vdt 

if MAINTAINER_MODE
CLEANFILES=*.ln

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

radtest_ln=main.ln gram.ln input.ln debugmod.ln
lint: $(radtest_ln)
	$(LINT.c) -u $(radtest_ln) -L../lib -llog -lrad 

FILELIST:; @echo gram.y > .list
endif

