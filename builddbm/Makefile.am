# $Id$
bin_PROGRAMS = builddbm
builddbm_SOURCES = builddbm.c 
builddbm_LDADD = -L ../radlib -lrad -llog -ldebug @RADIUSD_LDADD@
INCLUDES=-I$(srcdir) -I$(top_srcdir) -I../include @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(builddbm_SOURCES:.c=.ln)
	$(LINT.c) -u $(builddbm_SOURCES:.c=.ln) $(builddbm_LDADD)

endif

