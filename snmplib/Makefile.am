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

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out
lint:;
endif

EXTRA_DIST=COPYING.LIB README
noinst_LIBRARIES=libsnmp.a
libsnmp_a_SOURCES=asn1.c snmp_mem.c snmp_oid.c snmp_pdu.c \
                  snmp_recv.c snmp_send.c snmp_sess.c snmp_var.c \
                  snmp_err.c snmp_mib.c

INCLUDES= -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

