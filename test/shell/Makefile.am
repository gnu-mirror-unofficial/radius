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

TESTS=runtest.sh
TESTS_ENVIRONMENT=\
 TOOL=radiusd\
 AWK=$(AWK)\
 BUILDDIR=`cd $(top_builddir); pwd`\
 SOURCEDIR=`cd $(top_srcdir); pwd`

EXTRA_DIST = runtest.sh shell.m4 radiusd-stamp proxy-stamp radiusd radiusd.proxy
MAINTAINERCLEANFILES = radiusd-stamp proxy-stamp

maintainer-clean-local:; -rm -rf radiusd radiusd.proxy

M4_DEFINES=-DBUILDDIR=`cd $(top_builddir); pwd` \
           -DSOURCEDIR=`cd $(top_srcdir); pwd`

radiusd-stamp: $(srcdir)/../proto.m4 $(srcdir)/shell.m4 $(srcdir)/../radiusd.m4
	$(M4) $(M4_DEFINES) $(srcdir)/../proto.m4 $(srcdir)/shell.m4 $(srcdir)/../radiusd.m4|$(SHELL)
	touch radiusd-stamp

proxy-stamp: $(srcdir)/../proto.m4 $(srcdir)/shell.m4 $(srcdir)/../proxy.m4
	$(M4) $(M4_DEFINES) $(srcdir)/../proto.m4 $(srcdir)/shell.m4 $(srcdir)/../proxy.m4|$(SHELL)
	touch proxy-stamp

all: radiusd-stamp proxy-stamp 
