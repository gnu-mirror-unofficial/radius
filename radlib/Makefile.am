# $Id$

if SQL
LIBSQL=libsql.a
libsql_a_SOURCES=mysql.c postgres.c
endif

noinst_LIBRARIES=librad.a $(LIBSQL) liblog.a libdebug.a 
librad_a_SOURCES=intl.c radpaths.c alloc.c radprintf.c raddb.c dict.c \
                 fixalloc.c iputil.c strerror.c strncasecmp.c \
                 md5.c md5crypt.c mem.c leakdetect.c obstack.c \
                 users_gram.c users_lex.c util.c client.c \
		 insist.c debug.c slist.c
liblog_a_SOURCES=log.c 
libdebug_a_SOURCES=debugmod.c

BUILT_SOURCES=users_gram.c users_lex.c
DISTCLEANFILES=users_gram.c users_lex.c
INCLUDES= -I$(srcdir) -I$(top_srcdir)/include @INCLUDEPATH@
EXTRA_DIST=users.y users.l mysql.c postgres.c

users_gram.c users_gram.h: $(srcdir)/users.y
	$(YACC) -vd @YACC_OPTS@ $(srcdir)/users.y
	sed -e 's/y\.tab\.\([ch]\)/users_gram\.\1/g;s/yy/uyy/g' y.tab.c > users_gram.c
	sed -e 's/y\.tab\.\([ch]\)/users_gram\.\1/g;s/yy/uyy/g' y.tab.h > users_gram.h

users_lex.c: $(srcdir)/users.l
	$(LEX) $(srcdir)/users.l
	sed -e 's/lex\.yy\.c/users_lex\.c/g;s/yy/uyy/g' lex.yy.c > users_lex.c

users_lex.o: users_lex.c users_gram.h $(top_srcdir)/include/parser.h
users_gram.o: users_gram.c users_gram.h $(top_srcdir)/include/parser.h

SUFFIXES=.S .c .ln .o .s
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

CLEANFILES=*.ln
LINTFLAGS=-gzra -fAI -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

llib-llog.ln: $(liblog_a_SOURCES:.c=.ln)
	$(LINT.c) -Clog $(liblog_a_SOURCES:.c=.ln)

llib-lrad.ln: $(librad_a_SOURCES:.c=.ln)  llib-llog.ln
	$(LINT.c) -Crad $(librad_a_SOURCES:.c=.ln) -L. -llog

llib-ldebug.ln: $(libdebug_a_SOURCES:.c=.ln) llib-llog.ln
	$(LINT.c) -Cdebug $(libdebug_a_SOURCES:.c=.ln) -L. -llog

llib-lsql.ln: $(libsql_a_SOURCES:.c=.ln) llib-llog.ln llib-lrad.ln
	$(LINT.c) -Csql $(libsql_a_SOURCES:.c=.ln) -L. -llog -lrad

lint:: llib-llog.ln llib-lrad.ln llib-ldebug.ln llib-lsql.ln

LIBSRC=leakdetect.c mem.c $(libsql_a_SOURCES)

LIBLIST:; @echo $(LIBSRC) > .list
endif
