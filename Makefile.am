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

if GUILE
SCMDIR=radscm
TESTDIR=test
TESTS=@top_srcdir@/test/test.sh
TESTS_ENVIRONMENT=BUILDDIR=$(top_builddir) SOURCEDIR=$(top_srcdir)
endif

SUBDIRS=m4 include radlib snmplib radiusd radwho radzap radlast raduse\
        radscripts elisp raddb client $(SCMDIR) $(TESTDIR) doc po

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} $(top_srcdir)/scripts/debug.sh $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)

lint::
	for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir lint; \
	done
endif

EXTRA_DIST=doc mibs scripts contrib ylwrap

dist-hook:
	-(cd $(distdir); \
	 find . \( -name CVS -o -name .emacs.desktop -o -name .deps -o \
                   -name .cvsignore -o -name '*~' -o -name core \) \
		   -exec rm -rf {} \; )

