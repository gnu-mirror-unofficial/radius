# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

AUTOMAKE_OPTIONS = 1.7.1 readme-alpha
ACLOCAL_AMFLAGS = -I m4

SUBDIRS= intl m4 include lib sql snmplib radscm radiusd radwho radzap radlast\
        radscripts elisp raddb db client radtest examples doc po\
        mibs scripts contrib 

if MAINTAINER_MODE
MAINTAINERCLEANFILES=core *~ err out

debugmod:; here=`cd $(top_srcdir); pwd`; \
           MAKE=${MAKE} \
           $$here/scripts/debug.sh \
                 $$here/scripts/debugmod.m4 lib $(SUBDIRS)

webdoc:;   $(MAKE) -C doc/texinfo webdoc

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

distcleancheck_listfiles = \
	find . -type f -exec sh -c 'test -f $(top_srcdir)/{} || echo {}' \;

## Override distcheck rule.
distcheck: dist
	$(am__remove_distdir)
	GZIP=$(GZIP_ENV) gunzip -c $(distdir).tar.gz | $(AMTAR) xf -
	chmod -R a-w $(distdir); chmod a+w $(distdir)
	mkdir $(distdir)/=build
	mkdir $(distdir)/=inst
	chmod a-w $(distdir)
	dc_install_base=`$(am__cd) $(distdir)/=inst && pwd` \
	 && cd $(distdir)/=build \
	 && ../configure --srcdir=.. --prefix=$$dc_install_base \
	$(DISTCHECK_CONFIGURE_FLAGS) \
	 && $(MAKE) $(AM_MAKEFLAGS) \
	 && $(MAKE) $(AM_MAKEFLAGS) dvi \
	 && $(MAKE) $(AM_MAKEFLAGS) check \
	 && $(MAKE) $(AM_MAKEFLAGS) install \
	 && $(MAKE) $(AM_MAKEFLAGS) installcheck \
	 && $(MAKE) $(AM_MAKEFLAGS) uninstall \
	 && $(MAKE) $(AM_MAKEFLAGS) dist-gzip \
	 && rm -f $(distdir).tar.gz \
	 && $(MAKE) $(AM_MAKEFLAGS) distcleancheck
	$(am__remove_distdir)
	@echo "$(distdir).tar.gz is ready for distribution" | \
	 sed 'h;s/./=/g;p;x;p;x'
 

