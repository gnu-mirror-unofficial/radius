# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

endif

bin_PROGRAMS    = radwho
radwho_SOURCES = radwho.c 
radwho_LDADD   = -L ../radlib -lrad -llog -ldebug
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@
