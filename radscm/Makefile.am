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

bin_PROGRAMS=radscm
radscm_SOURCES=main.c radscm.c
INCLUDES  = -I$(top_srcdir)/include @INCLUDEPATH@ @GUILE_INCLUDES@
CPPFLAGS=-DDATADIR=\"$(pkgdatadir)\"
ETAGS_ARGS = --regex='/SCM_\(GLOBAL_\)?\(G?PROC\|G?PROC1\|SYMBOL\|VCELL\|CONST_LONG\).*\"\([^\"]\)*\"/\3/' \
   --regex='/[ \t]*SCM_[G]?DEFINE1?[ \t]*(\([^,]*\),[^,]*/\1/'

radscm_LDADD=@GUILE_LIBS@ ../radlib/librad.la ../radlib/libdebug.la ../radlib/liblog.la
pkgdata_DATA=boot.scm session.scm radctl.scm guile-procedures.txt
BUILT_SOURCES=radscm.x radscm.doc 

EXTRA_DIST=boot.scm session.scm radctl.scm radscm.x radscm.doc 

GUILE_DOC_SNARF=$(top_srcdir)/scripts/guile/guile-doc-snarf

SUFFIXES=.x .doc

.c.x:
	$(GUILE_DOC_SNARF) $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) \
                           $< > $@ || { rm $@; false; }

.c.doc:
	$(GUILE_DOC_SNARF) $< $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) \
                           $< > /dev/null || { rm $@; false; }

guile-procedures.txt: $(srcdir)/radscm.doc
	cat $(srcdir)/radscm.doc > $@

if MAINTAINER_MODE

## Add -MG to make the .x magic work with auto-dep code.
MKDEP = $(CC) -M -MG $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)


LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radscm_SOURCES:.c=.ln)
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) $(radscm_LDADD)

endif

