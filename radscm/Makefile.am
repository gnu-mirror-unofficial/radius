# This file is part of GNU Radius.
# Copyright (C) 2001,2003 Free Software Foundation, Inc.
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

noinst_LIBRARIES=@LIBRADSCM@
EXTRA_LIBRARIES=libradscm.a libservscm.a
bin_PROGRAMS=@RADSCM@
bin_SCRIPTS=@RADSESSION@
EXTRA_PROGRAMS=radscm
EXTRA_SCRIPTS=radsession

libradscm_a_SOURCES= \
 rscm_avl.c\
 rscm_dict.c\
 rscm_syslog.c\
 rscm_utmp.c\
 rscm_lib.c\
 radscm.c

libservscm_a_SOURCES= \
 rscm_radlog.c\
 rscm_rewrite.c\
 rscm_sql.c

radscm_SOURCES=main.c radscm.c

schemedir=$(pkgdatadir)/$(VERSION)/scheme
scheme_DATA=boot.scm ttl.scm @GUILE_PROCEDURES_TXT@
DOT_X_FILES=\
 rscm_avl.x\
 rscm_dict.x\
 rscm_radlog.x\
 rscm_rewrite.x\
 rscm_syslog.x\
 rscm_sql.x\
 rscm_utmp.x\
 rscm_lib.x\
 radscm.x
DOT_DOC_FILES=$(DOT_X_FILES:.x=.doc)
BUILT_SOURCES=@RADSCM_BUILT_SOURCES_LIST@
EXTRA_DIST=boot.scm ttl.scm ipalloc.scm radsession.in
CLEANFILES = *.x *.doc radsession guile-procedures.txt

radsession: $(srcdir)/radsession.in
	sed 's,BINDIR,$(bindir),' $? > $@

radscm_LDADD=@GUILE_LIBS@ ./libradscm.a ../lib/liblog.la @LIBGNURADIUS@ ../lib/libdebug.la @LIBINTL@

INCLUDES  = -I$(top_builddir) -I$(top_srcdir)/include -I$(srcdir) -I. @INCLUDEPATH@ @GUILE_INCLUDES@
AM_CPPFLAGS=-DDATADIR=\"$(schemedir)\"
ETAGS_ARGS = --regex='/SCM_\(GLOBAL_\)?\(G?PROC\|G?PROC1\|SYMBOL\|VCELL\|CONST_LONG\).*\"\([^\"]\)*\"/\3/' \
   --regex='/[ \t]*SCM_[G]?DEFINE1?[ \t]*(\([^,]*\),[^,]*/\1/'

GUILE_DOC_SNARF=$(top_srcdir)/scripts/guile/$(GUILE_SNARF_VERSION)/guile-doc-snarf

SUFFIXES=.x .doc

.c.x:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) -o $@ \
                           $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) 

.c.doc:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) -d -o $@ \
                           $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) 

guile-procedures.txt: $(DOT_DOC_FILES)
	cat $(DOT_DOC_FILES) > $@

## Add -MG to make the .x magic work with auto-dep code.
MKDEP = $(CC) -M -MG $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)

if MAINTAINER_MODE

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-lradscm.ln: $(libradscm_a_SOURCES:.c=.ln)
	$(LINT.c) -Cradscm $(libradscm_a_SOURCES:.c=.ln) 

lint: $(radscm_SOURCES:.c=.ln) llib-lradscm.ln
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) -lradscm -L../lib -llog -lrad -ldebug

endif

