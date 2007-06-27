# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2007 Free Software Foundation, Inc.
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

man_MANS=builddbm.8 radctl.8 radiusd.8\
	 radping.8 radzap.8\
         radgrep.1 radlast.1 raduse.1 radwho.1
EXTRA_DIST=builddbm.8.man radctl.8.man radiusd.8.man\
	   radping.8.man radzap.8.man\
           radgrep.1.man radlast.1.man raduse.1.man radwho.1.man

CLEANFILES=$(man_MANS)

dist-hook:
	-(cd $(distdir); rm -f $(CLEANFILES))

builddbm.8: $(srcdir)/builddbm.8.man
	soelim $? > $@

radctl.8: $(srcdir)/radctl.8.man
	soelim $? > $@

radgrep.1: $(srcdir)/radgrep.1.man
	soelim $? > $@

radiusd.8: $(srcdir)/radiusd.8.man
	soelim $? > $@

radlast.1: $(srcdir)/radlast.1.man
	soelim $? > $@

radping.8: $(srcdir)/radping.8.man
	soelim $? > $@

raduse.1: $(srcdir)/raduse.1.man
	soelim $? > $@

radwho.1: $(srcdir)/radwho.1.man
	soelim $? > $@

radzap.8: $(srcdir)/radzap.8.man
	soelim $? > $@

