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

sbin_PROGRAMS   = radiusd
radiusd_SOURCES = \
 acct.c\
 auth.c\
 builddbm.c\
 checkrad.c\
 config.c\
 config_kw.c\
 config_tok.h\
 debugmod.c\
 exec.c\
 files.c\
 log.c\
 menu.c\
 pam.c\
 proxy.c\
 radck.c\
 radius.c\
 radiusd.c\
 radutil.c\
 rewrite.c\
 scheme.c\
 snmpserv.c\
 sql.c\
 stat.c\
 timestr.c\
 version.c

radiusd_LDADD = @LEXLIB@ @SQLLIB@ ../snmplib/libradsnmp.a @RADIUSD_LDADD@ ../radlib/librad.la 
BUILT_SOURCES   = config.c config_kw.c rewrite.c
MAINTAINERCLEANFILES=config.c config_tok.h config_kw.c rewrite.c y.output
INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp -I$(top_srcdir)/radlib @INCLUDEPATH@ @GUILE_INCLUDES@
EXTRA_DIST      = config.y config.kw rewrite.y .gdbinit
YLWRAP = $(SHELL) $(top_srcdir)/ylwrap
GPERF=@GPERF@

config.c config_tok.h: $(srcdir)/config.y
	$(YLWRAP) "$(YACC)" $(srcdir)/config.y \
                  y.tab.c config.c y.tab.h config_tok.h y.output y.output \
                  -- -yy cc -vdt 

config_kw.c: $(srcdir)/config.kw
	$(YLWRAP) "$(GPERF)" $(srcdir)/config.kw \
	   	  config_kw.c config_kw.c \
                  -- -yy cc -stdout -k1,2,6,7,11,13,$$ -t 

config.o: config.c ../include/radiusd.h 

rewrite.c: $(srcdir)/rewrite.y
	$(YLWRAP) "$(YACC)" $(srcdir)/rewrite.y \
		  y.tab.c rewrite.c -- -yy rw_yy -vt

SUFFIXES=.S .c .ln .o .s

# Maintainer-specific code
if MAINTAINER_MODE

CLEANFILES=*.ln
LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 $(INCLUDES)
radiusd_LNS=$(radiusd_SOURCES:.c=.ln)

.c.ln:
	$(LINT.c) -i $<

lint:  $(radiusd_LNS)
	$(LINT.c) -u $(radiusd_LNS) -L../radlib -lrad

SRCS=radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
         config.y pam.c proxy.c radius.c\
         timestr.c version.c log.c stat.c\
         snmpserv.c shmem.c radutil.c rewrite.y\
         checkrad.c radck.c builddbm.c

FILELIST:; @echo $(SRCS) > .list

endif

