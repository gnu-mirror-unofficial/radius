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
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out
lint:;
endif

noinst_LIBRARIES=libsnmp.a
libsnmp_a_SOURCES=asn1.c parse.c snmp_vars.c \
                  coexistance.c snmp_api.c snmp_error.c  \
                  mib.c snmp_api_error.c   \
                  snmp_msg.c \
                  snmp_pdu.c snmplib_debug.c
INCLUDES= -I$(srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

