# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, 2002, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

pamdir=@PAMDIR@
pam_LTLIBRARIES = @BUILD_PAM_RADIUS_LA@
EXTRA_LTLIBRARIES = pam_radius.la
pam_radius_la_SOURCES = pam_radius.c
pam_radius_la_LIBADD = -lpam ../../lib/librad.la ../../lib/libdebug.la @LTLIBINTL@
INCLUDES = -I$(top_builddir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

pam_radius_la_LDFLAGS = -module -avoid-version -no-undefined -rpath $(pamdir) \
 -Wl,-Bsymbolic

