# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

noinst_LIBRARIES=@LIBRADSCM@
EXTRA_LIBRARIES=libradscm.a libservscm.a
bin_PROGRAMS=@RADSCM@
EXTRA_PROGRAMS=radscm

libradscm_a_SOURCES= \
 rscm_avl.c\
 rscm_dict.c\
 rscm_syslog.c\
 rscm_utmp.c\
 rscm_lib.c\
 radscm.c\
 radscm.h

libservscm_a_SOURCES= \
 rscm_radlog.c \
 rscm_rewrite.c

radscm_SOURCES=main.c radscm.c

pkgdata_DATA=boot.scm session.scm ttl.scm @GUILE_PROCEDURES_TXT@
DOT_X_FILES=\
 rscm_avl.x\
 rscm_dict.x\
 rscm_radlog.x\
 rscm_rewrite.x\
 rscm_syslog.x\
 rscm_utmp.x\
 rscm_lib.x\
 radscm.x
DOT_DOC_FILES=$(DOT_X_FILES:.x=.doc)
BUILT_SOURCES=@RADSCM_BUILT_SOURCES@
EXTRA_DIST=boot.scm session.scm ttl.scm
CLEANFILES = *.x *.doc

radscm_LDADD=@GUILE_LIBS@ ./libradscm.a ../radlib/liblog.la ../radlib/librad.la ../radlib/libdebug.la 

INCLUDES  = -I$(top_srcdir)/include @INCLUDEPATH@ @GUILE_INCLUDES@
CPPFLAGS=-DDATADIR=\"$(pkgdatadir)\"
ETAGS_ARGS = --regex='/SCM_\(GLOBAL_\)?\(G?PROC\|G?PROC1\|SYMBOL\|VCELL\|CONST_LONG\).*\"\([^\"]\)*\"/\3/' \
   --regex='/[ \t]*SCM_[G]?DEFINE1?[ \t]*(\([^,]*\),[^,]*/\1/'

GUILE_DOC_SNARF=$(top_srcdir)/scripts/guile/guile-doc-snarf

SUFFIXES=.x .doc

.c.x:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) \
                           $< > $@ || { rm $@; false; }

.c.doc:
	AWK=$(AWK) \
	$(GUILE_DOC_SNARF) $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) \
                           $< > /dev/null || { rm $@; false; }

guile-procedures.txt: $(DOT_DOC_FILES)
	cat $(DOT_DOC_FILES) > $@

## Add -MG to make the .x magic work with auto-dep code.
MKDEP = $(CC) -M -MG $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)

if MAINTAINER_MODE

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radscm_SOURCES:.c=.ln)
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) $(radscm_LDADD)

endif

