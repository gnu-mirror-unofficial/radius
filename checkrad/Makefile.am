# $Id$
libexec_PROGRAMS    = checkrad
checkrad_SOURCES = checkrad.c netfinger.c compare.c config.c log.c debugmod.c
checkrad_LDADD   = -L ../radlib -lrad -L ../snmplib -lsnmp
INCLUDES        = -I$(top_srcdir)/include -I$(top_srcdir)/include/snmp @INCLUDEPATH@

SUFFIXES=.S .c .ln .o .s

if MAINTAINER_MODE
CFLAGS=-ggdb -DMAINTAINER_MODE=1
MAINTAINERCLEANFILES=core *~ err out

LINTFLAGS=-gezra -DHAVE_CONFIG_H=1 -DMAINTAINER_MODE=1 -I$(top_srcdir) $(INCLUDES)

.c.ln:
	$(LINT.c) -i $<

lint: $(checkrad_SOURCES:.c=.ln)
	$(LINT.c) -u $(checkrad_SOURCES:.c=.ln) $(checkrad_LDADD)


FILELIST:; @echo $(checkrad_SOURCES) > .list
endif

