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

man_MANS=builddbm.8 radctl.8 radiusd.8\
	 radping.8 radzap.8\
         radgrep.1 radlast.1 raduse.1 radwho.1
CLEANFILES=$(man_MANS)

dist-hook:
	-(cd $(distdir); rm -f $(CLEANFILES))

builddbm.8: $(srcdir)/builddbm.8.man
	soelim $(srcdir)/builddbm.8.man > builddbm.8

radctl.8: $(srcdir)/radctl.8.man
	soelim $(srcdir)/radctl.8.man > radctl.8

radgrep.1: $(srcdir)/radgrep.1.man
	soelim $(srcdir)/radgrep.1.man > radgrep.1

radiusd.8: $(srcdir)/radiusd.8.man
	soelim $(srcdir)/radiusd.8.man > radiusd.8

radlast.1: $(srcdir)/radlast.1.man
	soelim $(srcdir)/radlast.1.man > radlast.1

radping.8: $(srcdir)/radping.8.man
	soelim $(srcdir)/radping.8.man > radping.8

raduse.1: $(srcdir)/raduse.1.man
	soelim $(srcdir)/raduse.1.man > raduse.1

radwho.1: $(srcdir)/radwho.1.man
	soelim $(srcdir)/radwho.1.man > radwho.1 

radzap.8: $(srcdir)/radzap.8.man
	soelim $(srcdir)/radzap.8.man > radzap.8
