if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
endif

bin_PROGRAMS=radscm
radscm_SOURCES=main.c radscm.c
INCLUDES  = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@ @GUILE_INCLUDES@
CPPFLAGS=-DDATADIR=\"$(pkgdatadir)\"
radscm_LDADD=@GUILE_LIBS@ -L../radlib -lrad -ldebug -llog
pkgdata_DATA=boot.scm session.scm radctl.scm
EXTRA_DIST=boot.scm session.scm radctl.scm
