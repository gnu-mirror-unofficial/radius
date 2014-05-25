# This file is part of GNU Radius.
# Copyright (C) 2001, 2003, 2004, 2010, 2013 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

lib_LTLIBRARIES=libradscm.la
noinst_LIBRARIES=libservscm.a
bin_SCRIPTS=radsession

libradscm_la_SOURCES= \
 rscm_avl.c\
 rscm_dict.c\
 rscm_hash.c\
 rscm_syslog.c\
 rscm_utmp.c\
 rscm_lib.c\
 radscm.c

libservscm_a_SOURCES= \
 rscm_radlog.c\
 rscm_rewrite.c\
 rscm_sql.c

#sitedir = @GUILE_SITE@/$(PACKAGE)
sitedir=$(pkgdatadir)/$(VERSION)/scheme

site_DATA=\
 gnuradius.scm\
 radiusd.scm\
 ttl.scm\
 ipalloc.scm

DOT_X_FILES=\
 rscm_avl.x\
 rscm_dict.x\
 rscm_hash.x\
 rscm_radlog.x\
 rscm_rewrite.x\
 rscm_syslog.x\
 rscm_sql.x\
 rscm_utmp.x\
 rscm_lib.x\
 radscm.x
DOT_DOC_FILES=$(DOT_X_FILES:.x=.doc)
BUILT_SOURCES=gnuradius.scm radiusd.scm
EXTRA_DIST=ttl.scm ipalloc.scm radsession.in \
 gnuradius.scm4 radiusd.scm4
CLEANFILES = radsession gnuradius.scm radiusd.scm
DISTCLEANFILES=
AM_CPPFLAGS=\
 @RADIUS_INCLUDE_PATH@ -I$(srcdir) -I. @GUILE_INCLUDES@\
 -DDATADIR=\"$(sitedir)\"
radsession: $(srcdir)/radsession.in
	$(AM_V_GEN)sed 's,GUILE_BINDIR,$(GUILE_BINDIR),;s,SCHEMEDIR,$(sitedir),;s,PACKAGE_STRING,$(PACKAGE_STRING),' $? > $@

libradscm_la_LIBADD=@LIBGNURADIUS@ @LIBINTL@ @GUILE_LIBS@
libradscm_la_LDFLAGS = -rpath $(libdir) -version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@

SUFFIXES=.scm4 .scm

.scm4.scm:
	$(AM_V_GEN)m4 -DVERSION=$(VERSION) -DLIBDIR="$(libdir)" \
	   -DBUILDDIR="`cd $(top_builddir)/radscm;pwd`" \
	   -DSITEDIR='$(sitedir)' $< > $@

install-data-hook:
	@here=`pwd`; \
	 cd $(DESTDIR)$(libdir);\
	 if test -f libradscm.so; then \
	   $(LN_S) -f libradscm.so libguile-gnuradius-v-$(VERSION).so; \
	 fi; \
	 cd $$here

MAINTAINERCLEANFILES=
include ../gint/gint.mk

