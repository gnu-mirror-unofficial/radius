EXTRA_DIST=\
 Auth.exp\
 Acct-start.exp\
 Acct-stop.exp\
 Nested.exp\
 Prop.exp\
 Start.exp\
 Stop.exp\
 Testlist

all:;
	$(AWK) -v SRCDIR=`cd $(srcdir); pwd` -v CMD="$(LN_S)" -f $(top_srcdir)/scripts/mktest.awk $(srcdir)/Testlist|$(SHELL)
