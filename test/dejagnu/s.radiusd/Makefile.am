EXTRA_DIST=\
 Access.exp\
 Acct-start.exp\
 Execwait.exp\
 Hint.exp\
 Huntgroups.exp\
 Reply.exp\
 Stop.exp\
 Stress.exp\
 Acct-stop.exp\
 Auth.exp\
 Match.exp\
 Menu.exp\
 Rewrite.exp\
 Scheme.exp\
 Scheme-acct.exp\
 Start.exp\
 Begin.exp\
 Default.exp\
 Testlist

all:;
	$(AWK) -v SRCDIR=`cd $(srcdir); pwd` -v CMD="$(LN_S)" -f $(top_srcdir)/scripts/mktest.awk $(srcdir)/Testlist|$(SHELL)
