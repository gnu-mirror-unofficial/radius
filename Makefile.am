if SNMP
if DBM
SUBDIRS=include radlib snmplib radiusd radtest radwho radzap radlast raduse radctl radscripts checkrad builddbm doc po
else
SUBDIRS=include radlib snmplib radiusd radtest radwho radzap radlast raduse radctl radscripts checkrad doc po
endif
else
if DBM
SUBDIRS=include radlib radiusd radtest radzap radwho radlast raduse radctl radscripts checkrad builddbm doc po
else
SUBDIRS=include radlib radiusd radtest radzap radwho radlast raduse radctl radscripts checkrad doc po
endif
endif

if MAINTAINER_MODE
CFLAGS=-ggdb
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} $(top_srcdir)/scripts/debug.sh $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)
endif

EXTRA_DIST=include raddb doc mibs scripts

dist-hook:
	(cd $(distdir); \
	 rm -f radlib/users_gram.c radlib/users_lex.c \
	       radiusd/config.c radtest/y.tab.c radtest/lex.yy.c )

install-data-local:
	@if [ ! -d @ETC_DIR@/raddb ]; then \
		./install-sh -d -m 644 @ETC_DIR@ ; \
		cp -r raddb @ETC_DIR@ ; \
	fi
