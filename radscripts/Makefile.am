# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

sbin_SCRIPTS=radctl radauth 
bin_SCRIPTS=radping radgrep builddbm
EXTRA_DIST=radscripts.m4 radctl.m4 radauth.m4 \
           radping.m4 radgrep.m4 builddbm.m4
CLEANFILES=$(sbin_SCRIPTS) $(bin_SCRIPTS)
M4_DEFINES=-DSRCDIR=$(srcdir) -DPROGNAME=$(sbindir)/radiusd \
           -DBINDIR=$(bindir) -DSBINDIR=$(sbindir) -DDATADIR=$(pkgdatadir) \
           -DPIDFILE=$(RADPID_DIR)/radiusd.pid -DPS=$(PS) \
	   -DAWK=$(AWK) -DGETOPT=$(GETOPT)
radctl: $(srcdir)/radctl.m4
	$(M4) $(M4_DEFINES) $(srcdir)/radctl.m4 > radctl

radgrep: $(srcdir)/radgrep.m4
	$(M4) $(M4_DEFINES) $(srcdir)/radgrep.m4 > radgrep

radping: $(srcdir)/radping.m4
	$(M4) $(M4_DEFINES) $(srcdir)/radping.m4 > radping

radauth: $(srcdir)/radauth.m4
	$(M4) $(M4_DEFINES) $(srcdir)/radauth.m4 > radauth

builddbm: $(srcdir)/builddbm.m4
	$(M4) $(M4_DEFINES) $(srcdir)/builddbm.m4 > builddbm

# Maintainer-specific part
if MAINTAINER_MODE

lint:;

endif

