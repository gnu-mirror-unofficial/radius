EXTRA_DIST=\
 Access.exp\
 Acct-start.exp\
 Execwait.exp\
 Reply.exp\
 Stop.exp\
 Acct-stop.exp\
 Auth.exp\
 Match.exp\
 Menu.exp\
 Scheme.exp\
 Start.exp\
 Begin.exp\
 Default.exp\
 Testlist

all:;
	$(AWK) -vSRCDIR=`pwd` -f $(top_srcdir)/scripts/mktest.awk Testlist|$(SHELL)