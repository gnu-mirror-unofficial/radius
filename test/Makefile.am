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
INCLUDES=-I$(top_srcdir)/include @INCLUDEPATH@
noinst_PROGRAMS=findport
findport_SOURCES=findport.c
SUBDIRS=raddb proxy dejagnu shell
noinst_SCRIPTS=test.sh
EXTRA_DIST=test.sh.m4 radiusd.m4 proxy.m4 proto.m4
CLEANFILES=test.sh 

TESTS_ENVIRONMENT=BUILDDIR=$(top_builddir) SOURCEDIR=$(top_srcdir)

M4_DEFINES=-DBUILDDIR=`cd $(top_builddir); pwd` \
           -DSOURCEDIR=`cd $(top_srcdir); pwd`

test.sh: $(srcdir)/test.sh.m4
	$(M4) $(M4_DEFINES) $? > $@
	chmod 755 $@



