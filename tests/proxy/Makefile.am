# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003,2008 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

EXTRA_DIST = \
 client.conf.in\
 config.in\
 dictionary.in\
 hints\
 huntgroups\
 realms.in\
 sqlserver\
 users

ALLTARGETS= nastypes clients naslist

all: $(ALLTARGETS)

RADDB=$(top_srcdir)/raddb

nastypes: $(RADDB)/nastypes
	rm -f $@
	$(LN_S) $? $@

clients: ../raddb/clients
	rm -f $@
	$(LN_S) $? $@

naslist: ../raddb/naslist
	rm -f $@
	$(LN_S) $? $@

CLEANFILES=$(ALLTARGETS) dictionary client.conf config realms ports

distclean-local:; -rm -rf radiusd.pid log acct
