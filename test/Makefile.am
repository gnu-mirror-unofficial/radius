if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out
endif

noinst_PROGRAMS=findport
findport_SOURCES=findport.c
EXTRA_DIST=raddb test.sh test.scm
CLEANFILES=acct log raddb/config raddb/radctl.rc