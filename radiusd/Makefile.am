# $Id$

CFLAGS=$(MCFLAGS) -DCHECKRAD=\"${libexecdir}/checkrad\"

if SQL
LIBSQL=-lsql
endif

sbin_PROGRAMS   = radiusd
radiusd_SOURCES = radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
                  notify.c config.c pam.c proxy.c radius.c\
                  symtab.c timestr.c version.c log.c ippool.c stat.c\
                  snmpserv.c shmem.c radutil.c radctl.c\
                  rewrite.c debugmod.c
radiusd_LDADD   = @LEXLIB@ -L ../radlib -lrad $(LIBSQL) @RADIUSD_LDADD@
BUILT_SOURCES   = config.c rewrite.c
DISTCLEANFILES  = config.c y.output
INCLUDES        = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@
EXTRA_DIST      = config.y rewrite.y .gdbinit

config.c: $(srcdir)/config.y
	$(YACC) -v @YACC_OPTS@ $(srcdir)/config.y
	sed -e 's/y\.tab\.\([ch]\)/config\.\1/g;s/yy/conf_yy/g' y.tab.c > config.c

config.o: config.c ../include/radiusd.h ../include/ippool.h

rewrite.c: $(srcdir)/rewrite.y
	$(YACC) -v @YACC_OPTS@ $(srcdir)/rewrite.y
	sed -e 's/y\.tab\.\([ch]\)/rewrite\.\1/g;s/yy/rw_yy/g' y.tab.c > rewrite.c

SUFFIXES=.S .c .ln .o .s

# Maintainer-specific code
if MAINTAINER_MODE

MCFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out 
CLEANFILES=*.ln
LINTFLAGS=-gezr -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -DCHECKRAD=\"${libexecdir}/checkrad\" $(INCLUDES)
radiusd_LNS=$(radiusd_SOURCES:.c=.ln)

.c.ln:
	$(LINT.c) -i $<

lint:  $(radiusd_LNS)
	$(LINT.c) -u $(radiusd_LNS)

SRCS=radiusd.c acct.c auth.c exec.c files.c menu.c sql.c\
         notify.c config.y pam.c proxy.c radius.c\
         symtab.c timestr.c version.c log.c ippool.c stat.c\
         snmpserv.c shmem.c radutil.c radctl.c rewrite.y

FILELIST:; @echo $(SRCS) > .list

endif

