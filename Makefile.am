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

SUBDIRS=m4 include radlib sql snmplib radscm radiusd radwho radzap radlast\
        raduse radscripts elisp raddb db client test doc po mibs\
        scripts contrib

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} \
           $(top_srcdir)/scripts/debug.sh \
                 $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)

lint::
	for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir lint; \
	done

alpha: 
	$(MAKE) dist distdir=$(PACKAGE)-$(VERSION)-`date +'%Y%m%d'`

alphacheck: 
	$(MAKE) distcheck distdir=$(PACKAGE)-$(VERSION)-`date +'%Y%m%d'`

endif

EXTRA_DIST=ylwrap README-alpha

