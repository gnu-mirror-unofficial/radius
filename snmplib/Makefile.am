# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2004 Free Software Foundation, Inc.
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

EXTRA_DIST=COPYING.LIB README
noinst_LIBRARIES=libradsnmp.a
libradsnmp_a_SOURCES=asn1.c snmp_mem.c snmp_oid.c snmp_pdu.c \
                  snmp_recv.c snmp_send.c snmp_sess.c snmp_var.c \
                  snmp_err.c snmp_mib.c

INCLUDES = @RADIUS_INCLUDE_PATH@

