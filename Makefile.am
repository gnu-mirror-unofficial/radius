if SNMP
SNMPDIR=snmplib
endif

if DBM
DBMDIR=builddbm
endif

SUBDIRS=include radlib $(SNMPDIR) radiusd radtest radwho radzap radlast raduse radctl radscripts checkrad $(DBMDIR) doc po

if MAINTAINER_MODE
CFLAGS=-ggdb
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} $(top_srcdir)/scripts/debug.sh $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)
endif

EXTRA_DIST=include raddb doc mibs scripts test

dist-hook:
	(cd $(distdir); \
	 rm -f radlib/users_gram.c radlib/users_lex.c \
	       radiusd/config.c radtest/y.tab.c radtest/lex.yy.c )

install-data-local:
	@if [ ! -d @ETC_DIR@/raddb ]; then \
		./install-sh -d -m 644 @ETC_DIR@ ; \
		cp -r raddb @ETC_DIR@ ; \
	fi
