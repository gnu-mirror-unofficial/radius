# $Id$
EXTRA_DIST=screen.h

bin_PROGRAMS    = raduse
raduse_SOURCES = raduse.c screen.c display.c 
raduse_LDADD   = -lcurses -ltermcap -L ../radlib -lrad -llog -ldebug
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(raduse_SOURCES:.c=.ln)
	$(LINT.c) -u $(raduse_SOURCES:.c=.ln) $(raduse_LDADD)


endif
