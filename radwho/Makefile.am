# $Id$
bin_PROGRAMS    = radwho
radwho_SOURCES = radwho.c 
radwho_LDADD   = -L../radlib -lrad -llog -ldebug
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@


SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out
CLEANFILES=*.ln

LINTFLAGS=-gezra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(radwho_SOURCES:.c=.ln)
	$(LINT.c) -u $(radwho_SOURCES:.c=.ln) $(radwho_LDADD)



endif

