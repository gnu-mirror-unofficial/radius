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

pamdir=@PAMDIR@
pam_PROGRAMS = pam_radius.la
pam_radius_la_SOURCES = pam_radius.c
pam_radius_la_LDADD = -lpam ../../radlib/librad.la ../../radlib/libdebug.la 
INCLUDES = -I$(top_builddir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

raddbdir=@ETC_DIR@/raddb
raddb_DATA=client.conf
EXTRA_DIST=client.conf

pam_radius.lo: $(srcdir)/pam_radius.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(INCLUDES) $(srcdir)/pam_radius.c

pam_radius.la: pam_radius.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                 -o pam_radius.la pam_radius.lo $(pam_radius_la_LDADD) \
                 -rpath $(pamdir)
