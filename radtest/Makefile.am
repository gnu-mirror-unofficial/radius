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
radtest_SOURCES = main.c radtest.c gram.y input.l debugmod.c radtest.h
radtest_LDADD   = ../radlib/liblog.la ../radlib/librad.la 
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@
AM_YFLAGS = -vd @YACC_OPTS@

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1

FILELIST:; @echo gram.y > .list
endif

