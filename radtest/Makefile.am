# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003,2004 Free Software Foundation, Inc.
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

bin_PROGRAMS    = radtest
radtest_SOURCES = main.c gram.y input.l radtest.h
radtest_LDADD   = @LIBGNURADIUS@ @LIBINTL@
noinst_HEADERS  = gram.h
INCLUDES        = @RADIUS_INCLUDE_PATH@ -I$(srcdir) 
AM_YFLAGS = -vdt 

if MAINTAINER_MODE
CLEANFILES=*.ln

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

radtest_ln=main.ln gram.ln input.ln 
lint: $(radtest_ln)
	$(LINT.c) -u $(radtest_ln) -L../lib -llog -lrad 

endif

