# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out
endif
EXTRA_DIST=screen.h

bin_PROGRAMS    = raduse
raduse_SOURCES = raduse.c screen.c display.c 
raduse_LDADD   = -lcurses -ltermcap -L ../radlib -lrad -llog -ldebug
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@
