# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003 Free Software Foundation, Inc.
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

SUBDIRS = testsuite

sbin_PROGRAMS   = radiusd
radiusd_SOURCES = \
 acct.c\
 auth.c\
 builddbm.c\
 checkrad.c\
 config.c\
 debugmod.c\
 exec.c\
 files.c\
 forward.c\
 input.c\
 log.c\
 menu.c\
 pam.c\
 proxy.c\
 radck.c\
 radius.c\
 radiusd.c\
 radutil.c\
 request.c\
 rewrite.c\
 rpp.c\
 scheme.c\
 snmpserv.c\
 sql.c\
 stat.c\
 timestr.c\
 tsh.c\
 version.c

radiusd_LDADD = @LEXLIB@ @SQLLIB@ ../snmplib/libradsnmp.a @RADIUSD_LDADD_LIST@ @LIBGNURADIUS@ @READLINE_LIBS@ @LIBINTL@
BUILT_SOURCES   = config.c rewrite.c
MAINTAINERCLEANFILES=config.c rewrite.c y.output
INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp -I$(top_srcdir)/lib @INCLUDEPATH@ @GUILE_INCLUDES@
AM_CPPFLAGS=@PATHFLAGS@ -DRADIUS_DATADIR=\"$(pkgdatadir)/$(VERSION)\"
EXTRA_DIST      = config.y rewrite.y .gdbinit
YLWRAP = $(SHELL) $(top_srcdir)/scripts/ylwrap

config.c: $(srcdir)/config.y
	$(YLWRAP) "$(YACC)" $(srcdir)/config.y \
                  y.tab.c config.c y.output config.y.output \
                  -- -yy cc -vdt 

config.o: config.c ../include/radiusd.h 

rewrite.c: $(srcdir)/rewrite.y
	$(YLWRAP) "$(YACC)" $(srcdir)/rewrite.y \
		  y.tab.c rewrite.c y.output rewrite.y.output -- -yy rw_yy -vt

SUFFIXES=.S .c .ln .o .s

# Maintainer-specific code
if MAINTAINER_MODE

CLEANFILES=*.ln
LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) -I$(srcdir) $(INCLUDES)
radiusd_LNS=$(radiusd_SOURCES:.c=.ln)

.c.ln:
	$(LINT.c) -i $<

lint:  $(radiusd_LNS)
	$(LINT.c) -u $(radiusd_LNS) -L../lib -lrad

FILELIST:
	-echo $(radiusd_SOURCES) $(BUILT_SOURCES) $(EXTRA_DIST)|\
	tr -s ' ' '\n'|\
	sort|\
	uniq -u|\
	xargs grep -l '#define *RADIUS_MODULE' > .list

endif

