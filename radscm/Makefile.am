bin_PROGRAMS=radscm
radscm_SOURCES=main.c radscm.c
INCLUDES  = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@ @GUILE_INCLUDES@
CPPFLAGS=-DDATADIR=\"$(pkgdatadir)\"
radscm_LDADD=@GUILE_LIBS@ -L../radlib -lrad -ldebug -llog
pkgdata_DATA=boot.scm session.scm radctl.scm
EXTRA_DIST=boot.scm session.scm radctl.scm radscm.doc

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radscm_SOURCES:.c=.ln)
	$(LINT.c) -u $(radscm_SOURCES:.c=.ln) $(radscm_LDADD)

endif

