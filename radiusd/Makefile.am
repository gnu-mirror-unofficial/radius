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
LIBSQL=../radlib/libsql.la
endif

sbin_PROGRAMS   = radiusd
radiusd_SOURCES = radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
                  notify.c config.c pam.c proxy.c radius.c\
                  symtab.c timestr.c version.c log.c stat.c\
                  snmpserv.c shmem.c radutil.c radctl.c\
                  rewrite.c checkrad.c debugmod.c radck.c\
                  builddbm.c

radiusd_LDADD   = @LEXLIB@ ../radlib/librad.la -L../snmplib -lsnmp $(LIBSQL) @RADIUSD_LDADD@
BUILT_SOURCES   = config.c rewrite.c
DISTCLEANFILES  = config.c rewrite.c y.output
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp -I$(top_srcdir)/radlib @INCLUDEPATH@
EXTRA_DIST      = config.y rewrite.y .gdbinit
YLWRAP = $(SHELL) $(top_srcdir)/ylwrap

config.c: $(srcdir)/config.y
	$(YLWRAP) "$(YACC)" $(srcdir)/config.y \
                  y.tab.c config.c -- -yy conf_yy -v @YACC_OPTS@

config.o: config.c ../include/radiusd.h 

rewrite.c: $(srcdir)/rewrite.y
	$(YLWRAP) "$(YACC)" $(srcdir)/rewrite.y \
		  y.tab.c rewrite.c -- -yy rw_yy -v @YACC_OPTS@

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

