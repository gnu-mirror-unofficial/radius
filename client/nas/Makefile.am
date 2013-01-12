# This file is part of GNU Radius.
# Copyright (C) 2000-2003, 2007, 2010, 2013 Free Software Foundation, Inc.
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
# along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>.

libexec_SCRIPTS=@BUILD_NAS_SCM@
EXTRA_SCRIPTS=nas.scm
CLEANFILES=$(libexec_SCRIPTS)
EXTRA_DIST=nas.rc nas.scm.in
pppdir=/etc/ppp
raddbdir=$(sysconfdir)/raddb
raddb_DATA=nas.rc

nas.scm: $(srcdir)/nas.scm.in
	sed "s,BINDIR,$(bindir)," $(srcdir)/nas.scm.in > nas.scm

install-exec-hook:
	@if [ -d $(DESTDIR)$(pppdir) ]; then \
		echo "***************************************************"; \
		echo "If you wish to use nas.scm for accounting purposes,"; \
		echo "create the following symbolic links:"; \
		echo "  $(LN_S) $(libexecdir)/nas.scm $(pppdir)/ip-up"; \
		echo "  $(LN_S) $(libexecdir)/nas.scm $(pppdir)/ip-down"; \
		echo "***************************************************"; \
	else \
		echo "$(pppdir) does not exist."; \
	fi


