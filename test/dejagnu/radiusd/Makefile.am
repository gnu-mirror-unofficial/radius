EXTRA_DIST = \
 Start.in\
 Auth.in\
 Reply.in\
 Menu.in\
 Stop.in\
 [0-9][0-9][0-9]*.exp

SUFFIXES=.in .exp

exp:;
	$(AWK) -f $(top_srcdir)/scripts/mktest.awk Testlist|sh
