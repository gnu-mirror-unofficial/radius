# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LIBSRC=intl.c radpaths.c alloc.c attrprint.c dict.c fixalloc.c \
        iputil.c strerror.c strncasecmp.c \
        md5.c md5crypt.c mem.c leakdetect.c obstack.c \
        users.y users.l util.c client.c \
        insist.c debug.c

LIBLIST:; @echo $(LIBSRC) > .list
endif

noinst_LIBRARIES=librad.a liblog.a libdebug.a 
librad_a_SOURCES=intl.c radpaths.c alloc.c attrprint.c dict.c fixalloc.c \
                 iputil.c strerror.c strncasecmp.c \
                 md5.c md5crypt.c mem.c leakdetect.c obstack.c \
                 users_gram.c users_lex.c util.c client.c \
		 insist.c debug.c 
liblog_a_SOURCES=log.c 
libdebug_a_SOURCES=debugmod.c
BUILT_SOURCES=users_gram.c users_lex.c
DISTCLEANFILES=users_gram.c users_lex.c
INCLUDES= -I$(srcdir) -I$(top_srcdir)/include @INCLUDEPATH@
EXTRA_DIST=users.y users.l

users_gram.c users_gram.h: $(srcdir)/users.y
	$(YACC) -vd @YACC_OPTS@ $(srcdir)/users.y
	sed -e 's/y\.tab\.\([ch]\)/users_gram\.\1/g;s/yy/uyy/g' y.tab.c > users_gram.c
	sed -e 's/y\.tab\.\([ch]\)/users_gram\.\1/g;s/yy/uyy/g' y.tab.h > users_gram.h

users_lex.c: $(srcdir)/users.l
	$(LEX) $(srcdir)/users.l
	sed -e 's/lex\.yy\.c/users_lex\.c/g;s/yy/uyy/g' lex.yy.c > users_lex.c

users_lex.o: users_lex.c users_gram.h $(top_srcdir)/include/parser.h
users_gram.o: users_gram.c users_gram.h $(top_srcdir)/include/parser.h
