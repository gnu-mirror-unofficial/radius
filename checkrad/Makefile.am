# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

FILELIST:; @echo $(checkrad_SOURCES) > .list
endif

sbin_PROGRAMS    = checkrad
checkrad_SOURCES = checkrad.c netfinger.c compare.c config.c log.c debugmod.c
checkrad_LDADD   = -L ../radlib -lrad 
INCLUDES        = -I$(top_srcdir)/include @INCLUDEPATH@
