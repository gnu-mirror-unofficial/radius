if DBM
DBMDIR=builddbm
endif

if GUILE
SCMDIR=radscm
TESTDIR=test
TESTS=@top_srcdir@/test/test.sh
TESTS_ENVIRONMENT=BUILDDIR=$(top_builddir) SOURCEDIR=$(top_srcdir)
endif

SUBDIRS=include radlib snmplib radiusd  radwho radzap radlast raduse radscripts checkrad $(DBMDIR) $(SCMDIR) $(TESTDIR) doc po

if MAINTAINER_MODE
CFLAGS=-ggdb
MAINTAINERCLEANFILES=core *~ err out

debugmod:; MAKE=${MAKE} $(top_srcdir)/scripts/debug.sh $(top_srcdir)/scripts/debugmod.m4 radlib $(SUBDIRS)

lint::
	for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir lint; \
	done
	
endif

EXTRA_DIST=include raddb doc mibs scripts contrib

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
