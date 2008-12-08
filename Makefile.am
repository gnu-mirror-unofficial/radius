# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

AUTOMAKE_OPTIONS = gnits 1.8 dist-bzip2
ACLOCAL_AMFLAGS = -I m4 -I am

SUBDIRS= scripts include lib gnu sql snmplib radscm radiusd radwho \
         radzap radlast radscripts elisp raddb db client radtest \
         examples tests doc po\
         mibs contrib 

update-dictionary:
	here=`cd $(top_srcdir); pwd`;\
	cd $$here/raddb;\
	$(MAKE) update-dictionary;\
	cd $$here

# We never remove the contents of configuration directory and the
# info directory index
distuninstallcheck_listfiles = \
 find $(prefix) -type f -not -path '$(sysconfdir)/raddb/*'

.PHONY: make-ChangeLog
make-ChangeLog: 
	if test -d .git; then                                           \
	  $(top_srcdir)/build-aux/gitlog-to-changelog |                 \
            sed '/<unknown>$$/d' | fmt -s > $(distdir)/cl-t;            \
	  echo "" >> $(distdir)/cl-t;                                 \
	  echo "Local Variables:" >> $(distdir)/cl-t;                   \
	  echo "mode: change-log" >> $(distdir)/cl-t;                   \
	  echo "version-control: never"  >> $(distdir)/cl-t;            \
	  echo "buffer-read-only: t" >> $(distdir)/cl-t;                \
	  echo "End:" >> $(distdir)/cl-t;                               \
	  rm -f $(distdir)/ChangeLog;                                   \
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;                      \
	fi

dist-hook: make-ChangeLog

.PHONY: ChangeLog
ChangeLog: 
	if test -d .git; then                                           \
	  $(top_srcdir)/build-aux/gitlog-to-changelog |                 \
            sed '/<unknown>$$/d' | fmt -s > ChangeLog;                  \
	  echo "" >> ChangeLog;                                       \
	  echo "Local Variables:" >> ChangeLog;                         \
	  echo "mode: change-log" >> ChangeLog;                         \
	  echo "version-control: never"  >> ChangeLog;                  \
	  echo "buffer-read-only: t" >> ChangeLog;                      \
	  echo "End:" >> ChangeLog;                                     \
        fi

MAINTAINERCLEANFILES=core *~ err out

webdoc:;   $(MAKE) -C doc/texinfo webdoc

alpha: 
	$(MAKE) dist distdir=$(PACKAGE)-$(VERSION)-`date +'%Y%m%d'`

alphacheck: 
	$(MAKE) distcheck distdir=$(PACKAGE)-$(VERSION)-`date +'%Y%m%d'`


 

