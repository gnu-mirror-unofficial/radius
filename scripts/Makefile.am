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

SUBDIRS=guile
EXTRA_DIST=\
 config-conv\
 config-conv.awk\
 dot.emacs\
 debug.sh\
 debugmod.m4\
 dict.awk\
 mksnmp-h.awk\
 mktest.awk\
 texi2html.diff\
 ylwrap

EXTRA_PROGRAMS = pofilter

noinst_PROGRAMS = @build_POFILTER@
pofilter_SOURCES = pofilter.c
