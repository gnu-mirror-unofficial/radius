# $Id$

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

endif

bin_PROGRAMS    = radlast
radlast_SOURCES = radlast.c nasutil.c
radlast_LDADD   = -L ../radlib -lrad -llog -ldebug
INCLUDES = -I$(srcdir) -I$(top_srcdir) -I$(top_srcdir)/include @INCLUDEPATH@
