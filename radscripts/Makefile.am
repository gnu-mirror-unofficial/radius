# $Id$

sbin_PROGRAMS=radctl radauth radtest
radctl_SOURCES=radctl.m4
radauth_SOURCES=radauth.m4
bin_PROGRAMS=radping radgrep 
radping_SOURCES=radping.m4
radgrep_SOURCES=radgrep.m4
radtest_SOURCES=radtest.m4
EXTRA_DIST=radscripts.m4

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


# Maintainer-specific part
if MAINTAINER_MODE


endif

