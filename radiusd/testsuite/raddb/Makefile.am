# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003 Free Software Foundation, Inc.
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
 access.deny\
 ascend.bin\
 auth.bin\
 auth.scm\
 acct.scm.in\
 clients\
 client.conf.in\
 config.in\
 filter\
 hints\
 huntgroups\
 menus/menu1\
 menus/menu2\
 naslist\
 realms.in\
 sqlserver\
 users.in

ALLTARGETS= \
 dictionary\
 dict.ascend\
 dict.voip\
 dict.cisco\
 dict.tunnel\
 nastypes

all: $(ALLTARGETS)

RADDB=$(top_srcdir)/raddb
EXDIR=$(top_srcdir)/examples

dictionary: $(RADDB)/dictionary
	sed '/\$$INCLUDE dict\/compat/d;/\$$INCLUDE dict\/livingston/d;/#\$$INCLUDE dict\/ascend\.vs/d;s/#\$$INCLUDE dict\/cisco/\$$INCLUDE dict.cisco/;s/#\$$INCLUDE dict\/voip/\$$INCLUDE dict.voip/;s/#\$$INCLUDE dict\/ascend/\$$INCLUDE dict.ascend/;s/#\$$INCLUDE dict\/tunnel/\$$INCLUDE dict.tunnel/' $(RADDB)/dictionary > dictionary

dict.ascend: $(RADDB)/dict/ascend
	$(LN_S) $? $@

dict.voip: $(RADDB)/dict/voip
	$(LN_S) $? $@

dict.cisco: $(RADDB)/dict/cisco
	$(LN_S) $? $@

dict.tunnel: $(RADDB)/dict/tunnel
	$(LN_S) $? $@

nastypes: $(RADDB)/nastypes
	$(LN_S) $? $@

CLEANFILES=$(ALLTARGETS) config client.conf users acct.scm realms

distclean-local:; -rm -rf radiusd.pid log acct dict

