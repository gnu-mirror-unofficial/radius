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
bin_PROGRAMS    = radzap
radzap_SOURCES = radzap.c 
radzap_LDADD   = @LIBGNURADIUS@ @LIBINTL@
INCLUDES       = @RADIUS_INCLUDE_PATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CLEANFILES = *.ln

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radzap_SOURCES:.c=.ln)
	$(LINT.c) -u $(radzap_SOURCES:.c=.ln) -L../lib -llog -lrad -ldebug

endif

