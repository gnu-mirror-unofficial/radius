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

EXTRA_DIST = \
 access.deny\
 auth.bin\
 auth.scm\
 acct.scm.in\
 clients\
 client.conf.in\
 config.in\
 hints\
 huntgroups\
 menus/menu1\
 menus/menu2\
 naslist\
 realms\
 sqlserver\
 users.in

ALLTARGETS= \
 dictionary\
 dict.voip\
 dict.cisco\
 nastypes\
 rewrite

all: $(ALLTARGETS)

RADDB=$(top_srcdir)/raddb

dictionary: $(RADDB)/dictionary
	sed '/\$$INCLUDE dict\/compat/d;/\$$INCLUDE dict\/livingston/d;s/#\$$INCLUDE dict\/cisco/\$$INCLUDE dict.cisco/;s/#\$$INCLUDE dict\/voip/\$$INCLUDE dict.voip/' $(RADDB)/dictionary > dictionary

dict.voip: $(RADDB)/dict/voip
	$(LN_S) $? $@

dict.cisco: $(RADDB)/dict/cisco
	$(LN_S) $? $@

nastypes: $(RADDB)/nastypes
	$(LN_S) $? $@

rewrite: $(RADDB)/rewrite.full
	$(LN_S) $? $@

CLEANFILES=$(ALLTARGETS)