# This file is part of GNU RADIUS.
# Copyright (C) 2001 Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

raddbdir=@ETC_DIR@/raddb
raddb_files=access.deny \
clients \
config \
dictionary \
dictionary.ascend \
dictionary.cisco \
dictionary.compat \
dictionary.livingston \
dictionary.merit \
dictionary.tunnel \
dictionary.usr \
dictionary.voip \
hints \
huntgroups \
menus/menu1 \
menus/menu2 \
naslist \
nastypes \
radctl.rc \
realms \
rewrite \
rewrite.full \
sqlserver \
users 

EXTRA_DIST=$(raddb_files)

install-data-local:
	@if [ ! -d $(raddbdir) ]; then \
		${INSTALL} -d $(raddbdir); \
	fi
	@if [ -r $(raddbdir)/users ]; then \
		echo "Warning: The configuration directory $(raddbdir) already exists"; \
		cp $(raddbdir)/dictionary $(raddbdir)/dictionary.bak; \
		${INSTALL} -m 644 $(top_srcdir)/raddb/dictionary $(raddbdir)/dictionary; \
	else \
		for file in $(raddb_files); do \
			${INSTALL} -m 644 $(top_srcdir)/raddb/$$file $(raddbdir)/$$file; \
		done; \
	fi
