if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

endif

sbin_PROGRAMS  = radctl
radctl_SOURCES = radctl.c 
radctl_LDADD   = -L ../radlib -lrad -llog -ldebug
INCLUDES       = -I$(top_srcdir) -I$(top_srcdir)/include -I. @INCLUDEPATH@

