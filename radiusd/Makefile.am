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

if SQL
LIBSQL=-lsql
endif

sbin_PROGRAMS   = radiusd
radiusd_SOURCES = radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
                  notify.c config.c pam.c proxy.c radius.c\
                  symtab.c timestr.c version.c log.c stat.c\
                  snmpserv.c shmem.c radutil.c radctl.c\
                  rewrite.c checkrad.c debugmod.c radck.c\
                  builddbm.c

radiusd_LDADD   = @LEXLIB@ -L../radlib -lrad -L../snmplib -lsnmp $(LIBSQL) @RADIUSD_LDADD@
BUILT_SOURCES   = config.c rewrite.c
DISTCLEANFILES  = config.c rewrite.c y.output
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@
EXTRA_DIST      = config.y rewrite.y .gdbinit

config.c: $(srcdir)/config.y
	$(YACC) -v @YACC_OPTS@ $(srcdir)/config.y
	sed -e 's/y\.tab\.\([ch]\)/config\.\1/g;s/yy/conf_yy/g' y.tab.c > config.c

config.o: config.c ../include/radiusd.h 

rewrite.c: $(srcdir)/rewrite.y
	$(YACC) -v @YACC_OPTS@ $(srcdir)/rewrite.y
	sed -e 's/y\.tab\.\([ch]\)/rewrite\.\1/g;s/yy/rw_yy/g' y.tab.c > rewrite.c

SUFFIXES=.S .c .ln .o .s

# Maintainer-specific code
if MAINTAINER_MODE

CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out 
CLEANFILES=*.ln
LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 $(INCLUDES)
radiusd_LNS=$(radiusd_SOURCES:.c=.ln)

.c.ln:
	$(LINT.c) -i $<

lint:  $(radiusd_LNS)
	$(LINT.c) -u $(radiusd_LNS) -L../radlib -lrad

SRCS=radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
         notify.c config.y pam.c proxy.c radius.c\
         symtab.c timestr.c version.c log.c stat.c\
         snmpserv.c shmem.c radutil.c radctl.c rewrite.y\
         checkrad.c radck.c builddbm.c

FILELIST:; @echo $(SRCS) > .list

endif

