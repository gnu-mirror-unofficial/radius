# $Id$

sbin_PROGRAMS=radctl.sh
radctl_sh_SOURCES=radctl.sh.m4
bin_PROGRAMS=radping radgrep radauth
radping_SOURCES=radping.m4
radgrep_SOURCES=radgrep.m4
radauth_SOURCES=radauth.m4
EXTRA_DIST=radscripts.m4

radctl.sh: $(srcdir)/radctl.sh.m4
	$(M4) -DSRCDIR=$(srcdir) -DPROGNAME=$(sbindir)/radiusd \
	      -DPIDFILE=$(RADPID_DIR)/radiusd.pid -DPS=$(PS) \
              -DAWK=$(AWK) $(srcdir)/radctl.sh.m4 > radctl.sh

radgrep: $(srcdir)/radgrep.m4
	$(M4) -DSRCDIR=$(srcdir) $(srcdir)/radgrep.m4 > radgrep

radping: $(srcdir)/radping.m4
	$(M4) -DSRCDIR=$(srcdir) -DAWK=$(AWK) -DGETOPT=$(GETOPT) \
	       $(srcdir)/radping.m4 > radping

radauth: $(srcdir)/radauth.m4
	$(M4) -DSRCDIR=$(srcdir) -DRADTEST=$(bindir)/radtest \
              -DGETOPT=$(GETOPT) $(srcdir)/radauth.m4 > radauth


# Maintainer-specific part
if MAINTAINER_MODE


endif

