# This file is part of GNU Radius.
# Copyright (C) 2001,2003,2004 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

lib_LTLIBRARIES=@LIBRADSCM@
EXTRA_LTLIBRARIES=libradscm.la
EXTRA_LIBRARIES=libservscm.a
bin_SCRIPTS=@RADSESSION@
EXTRA_SCRIPTS=radsession

libradscm_la_SOURCES= \
 rscm_avl.c\
 rscm_dict.c\
 rscm_hash.c\
 rscm_syslog.c\
 rscm_utmp.c\
 rscm_lib.c\
 radscm.c

libservscm_a_SOURCES= \
 rscm_radlog.c\
 rscm_rewrite.c\
 rscm_sql.c

schemedir=$(pkgdatadir)/$(VERSION)/scheme
RADSCM_PKGDATA_FILES=guile-procedures.txt gnuradius.scm radiusd.scm
scheme_DATA=ttl.scm @RADSCM_PKGDATA@
DOT_X_FILES=\
 rscm_avl.x\
 rscm_dict.x\
 rscm_hash.x\
 rscm_radlog.x\
 rscm_rewrite.x\
 rscm_syslog.x\
 rscm_sql.x\
 rscm_utmp.x\
 rscm_lib.x\
 radscm.x
DOT_DOC_FILES=$(DOT_X_FILES:.x=.doc)
BUILT_SOURCES=@RADSCM_BUILT_SOURCES_LIST@
EXTRA_DIST=ttl.scm ipalloc.scm radsession.in \
 gnuradius.scm gnuradius.scm.in radiusd.scm radiusd.scm.in
CLEANFILES = *.exp *.inc *.x *.doc radsession gnuradius.scm radiusd.scm guile-procedures.txt

radsession: $(srcdir)/radsession.in
	sed 's,GUILE_BINDIR,$(GUILE_BINDIR),;s,SCHEMEDIR,$(schemedir),;s,PACKAGE_STRING,$(PACKAGE_STRING),' $? > $@

libradscm_la_LIBADD=@LIBGNURADIUS@ @LIBINTL@
libradscm_la_LDFLAGS = -rpath $(libdir) -version-info 0:0:0

INCLUDES  = -I$(top_builddir) -I$(top_srcdir)/include -I$(top_builddir)/include -I$(srcdir) -I. @INCLUDEPATH@ @GUILE_INCLUDES@
AM_CPPFLAGS=-DDATADIR=\"$(schemedir)\"
ETAGS_ARGS = --regex='/SCM_\(GLOBAL_\)?\(G?PROC\|G?PROC1\|SYMBOL\|VCELL\|CONST_LONG\).*\"\([^\"]\)*\"/\3/' \
   --regex='/[ \t]*SCM_[G]?DEFINE1?[ \t]*(\([^,]*\),[^,]*/\1/'

GUILE_DOC_SNARF=$(top_srcdir)/scripts/guile/$(GUILE_SNARF_VERSION)/guile-doc-snarf

SUFFIXES=.x .doc .inc .exp

.c.x:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) -o $@ \
                           $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) 

.c.doc:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) -d -o $@ \
                           $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) 

.c.inc:
	sed -n 's/SCM_DEFINE *(.[^,]*, *\"\([^"][^"]*\)\".*/[(export \1)]/p' $< > $@

.c.exp:
	sed -n 's/SCM_DEFINE *(.[^,]*, *\"\([^"][^"]*\)\".*/[ \1]dnl/p' $< > $@


guile-procedures.txt: $(DOT_DOC_FILES)
	cat $(DOT_DOC_FILES) > $@

gnuradius.scm: gnuradius.scm.in $(libradscm_la_SOURCES:.c=.inc)
	m4 -DVERSION=$(VERSION) -DLIBDIR=$(libdir) \
	   -DBUILDDIR=$(top_builddir)/radscm $< > $@

radiusd.scm: radiusd.scm.in $(libservscm_a_SOURCES:.c=.exp)
	m4 -DVERSION=$(VERSION) -DLIBDIR=$(libdir) \
	   -DBUILDDIR=$(top_builddir)/radscm $< > $@

## Add -MG to make the .x magic work with auto-dep code.
MKDEP = $(CC) -M -MG $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)

install-data-hook:
	@here=`pwd`; \
	 cd $(DESTDIR)$(libdir);\
	 if test -f libradscm.so; then \
	   $(LN_S) -f libradscm.so libguile-gnuradius-v-$(VERSION).so; \
	 fi; \
	 cd $$here


if MAINTAINER_MODE

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-lradscm.ln: $(libradscm_a_SOURCES:.c=.ln)
	$(LINT.c) -Cradscm $(libradscm_a_SOURCES:.c=.ln) 

lint: $(radscm_SOURCES:.c=.ln) llib-lradscm.ln
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) -lradscm -L../lib -llog -lrad -ldebug

endif

