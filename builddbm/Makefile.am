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

bin_PROGRAMS = builddbm
builddbm_SOURCES = builddbm.c 
builddbm_LDADD = -L../radlib -lrad -llog -ldebug @RADIUSD_LDADD@
INCLUDES=-I$(srcdir) -I$(top_srcdir) -I../include @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(builddbm_SOURCES:.c=.ln)
	$(LINT.c) -u $(builddbm_SOURCES:.c=.ln) $(builddbm_LDADD)

endif

