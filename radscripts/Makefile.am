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

sbin_SCRIPTS=radctl radauth radtest
bin_SCRIPTS=radping radgrep builddbm
EXTRA_DIST=radscripts.m4 radctl.m4 radauth.m4 radtest.m4 \
           radping.m4 radgrep.m4 builddbm.m4
CLEANFILES=$(sbin_SCRIPTS) $(bin_SCRIPTS)

if GUILE
GUILE_ENABLE=-DGUILE=1
endif

radctl: $(srcdir)/radctl.m4
	$(M4) -DSRCDIR=$(srcdir) -DPROGNAME=$(sbindir)/radiusd \
              -DBINDIR=$(bindir) -DDATADIR=$(pkgdatadir) \
              -DPIDFILE=$(RADPID_DIR)/radiusd.pid -DPS=$(PS) \
	      $(GUILE_ENABLE) \
	      -DAWK=$(AWK) $(srcdir)/radctl.m4 > radctl

radgrep: $(srcdir)/radgrep.m4
	$(M4) -DSRCDIR=$(srcdir) $(srcdir)/radgrep.m4 > radgrep

radping: $(srcdir)/radping.m4
	$(M4) -DSRCDIR=$(srcdir) -DAWK=$(AWK) -DGETOPT=$(GETOPT) \
	       $(srcdir)/radping.m4 > radping

radauth: $(srcdir)/radauth.m4
	$(M4) -DSRCDIR=$(srcdir) -DBINDIR=$(bindir) -DDATADIR=$(pkgdatadir) \
              -DGETOPT=$(GETOPT) $(srcdir)/radauth.m4 > radauth

radtest: $(srcdir)/radtest.m4
	$(M4) -DSRCDIR=$(srcdir) -DBINDIR=$(bindir) -DDATADIR=$(pkgdatadir) \
              $(GUILE_ENABLE) $(srcdir)/radtest.m4 > radtest

builddbm: $(srcdir)/builddbm.m4
	$(M4) -DSRCDIR=$(srcdir) -DSBINDIR=$(sbindir) \
              $(srcdir)/builddbm.m4 > builddbm

# Maintainer-specific part
if MAINTAINER_MODE

lint:;

endif

