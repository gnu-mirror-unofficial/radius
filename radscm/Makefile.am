# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
bin_PROGRAMS=radscm
radscm_SOURCES=main.c radscm.c
INCLUDES  = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@ @GUILE_INCLUDES@
CPPFLAGS=-DDATADIR=\"$(pkgdatadir)\"
radscm_LDADD=@GUILE_LIBS@ ../radlib/librad.la ../radlib/libdebug.la ../radlib/liblog.la
pkgdata_DATA=boot.scm session.scm radctl.scm
EXTRA_DIST=boot.scm session.scm radctl.scm radscm.doc

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1

LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radscm_SOURCES:.c=.ln)
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) $(radscm_LDADD)

endif

