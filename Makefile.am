if SNMP
SNMPDIR=snmplib
endif

if DBM
DBMDIR=builddbm
endif

if GUILE
SCMDIR=radscm
endif

SUBDIRS=include radlib $(SNMPDIR) radiusd  radwho radzap radlast raduse radscripts checkrad $(DBMDIR) $(SCMDIR) doc po

if MAINTAINER_MODE
CFLAGS=-ggdb
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} $(top_srcdir)/scripts/debug.sh $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)
endif

EXTRA_DIST=include raddb doc mibs scripts 

dist-hook:
	(cd $(distdir); \
	 rm -f radlib/users_gram.c radlib/users_lex.c radiusd/config.c; \
	 find . \( -name CVS -o -name .emacs.desktop -o -name .deps -o \
                   -name '*~' -o -name core \) -exec rm -rf {} \; )

install-data-local:
	@if [ ! -d @ETC_DIR@/raddb ]; then \
		${INSTALL} -d @ETC_DIR@ ; \
		cp -r $(top_srcdir)/raddb @ETC_DIR@ ; \
	fi
