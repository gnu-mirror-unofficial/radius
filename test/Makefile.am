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
endif
INCLUDES=-I$(top_srcdir)/include
noinst_PROGRAMS=findport
findport_SOURCES=findport.c
SUBDIRS=raddb proxy dejagnu
noinst_SCRIPTS=test.sh
EXTRA_DIST=test.sh.m4 radiusd.m4 dejagnu.m4 proxy.m4
CLEANFILES=acct log raddb/config raddb/client.conf 
#TESTS=@TESTDIR@
TESTS_ENVIRONMENT=BUILDDIR=$(top_builddir) SOURCEDIR=$(top_srcdir)

M4_DEFINES=-DBUILDDIR=`cd $(top_builddir); pwd` \
           -DSOURCEDIR=`cd $(top_srcdir); pwd`

test.sh: $(srcdir)/test.sh.m4
	$(M4) $(M4_DEFINES) $? > $@
	chmod 755 $@

radiusd-stamp: $(srcdir)/dejagnu.m4 $(srcdir)/radiusd.m4
	$(M4) $(M4_DEFINES) $(srcdir)/dejagnu.m4 $(srcdir)/radiusd.m4|$(SHELL)
	touch radiusd-stamp

proxy-stamp: $(srcdir)/dejagnu.m4 $(srcdir)/proxy.m4
	$(M4) $(M4_DEFINES) $(srcdir)/dejagnu.m4 $(srcdir)/proxy.m4|$(SHELL)
	touch proxy-stamp


all: test.sh radiusd-stamp proxy-stamp