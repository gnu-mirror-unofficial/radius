# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

endif

noinst_LIBRARIES=libsnmp.a
libsnmp_a_SOURCES=asn1.c parse.c snmp_vars.c \
                  coexistance.c snmp_api.c snmp_error.c  \
                  mib.c snmp_api_error.c   \
                  snmp_msg.c \
                  snmp_pdu.c snmplib_debug.c
INCLUDES= -I$(srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

