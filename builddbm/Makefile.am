# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

endif

bin_PROGRAMS = builddbm
builddbm_SOURCES = builddbm.c 
builddbm_LDADD = -L ../radlib -lrad -llog -ldebug @RADIUSD_LDADD@
INCLUDES=-I$(srcdir) -I$(top_srcdir) -I../include @INCLUDEPATH@
