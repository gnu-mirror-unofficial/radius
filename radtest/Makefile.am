# $Id$
if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1

FILELIST:; @echo gram.y > .list
	
endif

bin_PROGRAMS    = radtest
radtest_SOURCES = main.c radtest.c y.tab.c lex.yy.c symtab.c debugmod.c
radtest_LDADD   = -L ../radlib -lrad -llog 
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) @INCLUDEPATH@
EXTRA_DIST      = gram.y input.l radtest.h

y.tab.c y.tab.h: $(srcdir)/gram.y
	$(YACC) -vd @YACC_OPTS@ $(srcdir)/gram.y

lex.yy.c: $(srcdir)/input.l
	$(LEX) $(srcdir)/input.l

y.tab.o: y.tab.c y.tab.h
lex.yy.o: lex.yy.c y.tab.h
