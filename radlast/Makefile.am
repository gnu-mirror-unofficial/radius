# $Id$

bin_PROGRAMS    = radlast
radlast_SOURCES = radlast.c nasutil.c
radlast_LDADD   = -L../radlib -lrad -llog -ldebug
INCLUDES = -I$(srcdir) -I$(top_srcdir) -I$(top_srcdir)/include @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radlast_SOURCES:.c=.ln)
	$(LINT.c) -u $(radlast_SOURCES:.c=.ln) $(radlast_LDADD)

endif

