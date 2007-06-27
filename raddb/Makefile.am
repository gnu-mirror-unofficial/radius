# This file is part of GNU Radius.
# Copyright (C) 2001,2003,2007 Free Software Foundation, Inc.
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
#

raddbdir=$(sysconfdir)/raddb
raddb_subdirs=dict 

rewritedir=$(pkgdatadir)/$(VERSION)/rewrite

dictionaries=\
 dict/ascend\
 dict/ascend.vs\
 dict/cisco\
 dict/compat\
 dict/livingston\
 dict/microsoft\
 dict/standard\
 dict/tunnel\
 dict/usr\
 dict/voip

raddb_files_644=\
 access.deny\
 config\
 dictionary\
 hints\
 huntgroups\
 naslist\
 nastypes\
 realms\
 sqlserver 

raddb_files_600 = clients client.conf users 
raddb_files=$(raddb_files_600) $(raddb_files_644)

rewrite_DATA = checknas.rw log-hook.rw nas-ip.rw

EXTRA_DIST=$(raddb_files) $(dictionaries) client.conf.in config.in $(rewrite_DATA) 
DISTCLEANFILES=client.conf

update-dictionary:
	if [ -s $(DESTDIR)$(raddbdir)/dictionary.grad.1.0 ]; then \
		echo "Backup dicionary file found. It seems you have already run make install-dictionary"; \
	else\
		$(AWK) -f $(top_srcdir)/scripts/update-dict.awk\
                    $(DESTDIR)$(raddbdir)/dictionary\
                    $(top_srcdir)/raddb/dictionary\
                    $(top_srcdir)/raddb/dict/standard > $@-t; \
		if test -s $@-t; then \
		    mv $(DESTDIR)$(raddbdir)/dictionary \
                      $(DESTDIR)$(raddbdir)/dictionary.grad.1.0; \
		    mv $@-t $(DESTDIR)$(raddbdir)/dictionary;\
	        fi; \
	fi; \
        for file in $(dictionaries); do \
		${INSTALL} -m 644 $(top_srcdir)/raddb/$$file $(DESTDIR)$(raddbdir)/$$file; \
        done; 

install-data-local:
	@if [ ! -d $(DESTDIR)$(raddbdir) ]; then \
		${INSTALL} -d $(DESTDIR)$(raddbdir); \
	fi
	@for dir in $(raddb_subdirs); do \
		if [ ! -d $(DESTDIR)$(raddbdir)/$$dir ]; then \
			${INSTALL} -d $(DESTDIR)$(raddbdir)/$$dir; \
		fi; \
	done
	@if [ -r $(DESTDIR)$(raddbdir)/users ]; then \
		echo '================================================================='; \
		echo "Warning: The configuration directory $(raddbdir) already exists"; \
		echo "Make sure your dictionary is up to date!"; \
		echo '================================================================='; \
	else \
		for file in $(raddb_files_644); do \
			${INSTALL} -m 644 $(top_srcdir)/raddb/$$file $(DESTDIR)$(raddbdir)/$$file; \
		done; \
		for file in $(raddb_files_600); do \
			${INSTALL} -m 600 $(top_srcdir)/raddb/$$file $(DESTDIR)$(raddbdir)/$$file; \
		done; \
	        for file in $(dictionaries); do \
		        ${INSTALL} -m 644 $(top_srcdir)/raddb/$$file $(DESTDIR)$(raddbdir)/$$file; \
	        done;\
	fi

