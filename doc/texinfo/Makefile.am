# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

info_TEXINFOS=radius.texi
radius_TEXINFOS=acct.texi\
 attributes.texi\
 auth.texi\
 bugs.texi\
 builddbm.texi\
 client.texi\
 config.texi\
 configure.texi\
 debug.texi\
 extensions.texi\
 intro.texi\
 invoke.texi\
 logging.texi\
 naming.texi\
 operation.texi\
 programs.texi\
 radauth.texi\
 radctl.texi\
 radgrep.texi\
 radlast.texi\
 radping.texi\
 radscm.texi\
 raduse.texi\
 radwho.texi\
 radzap.texi\
 version.texi

EXTRA_DIST=index.html.in

if MAINTAINER_MODE

html: html_mono html_node html_chapter

html_node:
	texi2html=`cd $(top_srcdir);pwd`/scripts/texi2html; \
	if ! test -d html_node; then mkdir html_node; fi; \
	cd html_node; \
	$$texi2html -menu -split_node ../radius.texi

html_chapter:
	texi2html=`cd $(top_srcdir);pwd`/scripts/texi2html; \
	if ! test -d html_chapter; then mkdir html_chapter; fi; \
	cd html_chapter; \
	$$texi2html -menu -split_chapter ../radius.texi

html_mono:
	texi2html=`cd $(top_srcdir);pwd`/scripts/texi2html; \
	if ! test -d html_mono; then mkdir html_mono; fi; \
	cd html_mono; \
	$$texi2html -menu -monolithic ../radius.texi

ps: radius.ps

radius.ps: radius.dvi
	dvips -oradius.ps radius.dvi

text: radius.text

radius.text: radius.info
	info --node=Top --subnodes --out radius.text -f radius.info

radius.info.tar.gz:
	tar cfz radius.info.tar.gz radius.info*

radius.dvi.gz: radius.dvi
	gzip -c radius.dvi > radius.dvi.gz

radius.ps.gz: radius.ps
	gzip -c radius.ps > radius.ps.gz

radius.texi.tar.gz:
	tar cfz radius.texi.tar.gz *.texi

WEB_HTML=\
 html_mono\
 html_node\
 html_chapter

WEB_BIN=\
 radius.info.tar.gz\
 radius.dvi.gz\
 radius.ps.gz\
 radius.texi.tar.gz\
 radius.text

WEBDOC=$(WEB_HTML) $(WEB_BIN) 

docdir: $(WEBDOC) index.html
	if ! test -d $(docdir); then mkdir $(docdir); fi; \
	here=`cd $(srcdir) && pwd`; \
	docdir=`cd $(docdir) && pwd`; \
	for file in $(WEB_HTML) index.html; do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$docdir/$$file; \
	  else \
	    test -f $$docdir/$$file \
	    || ln $$here/$$file $$docdir/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$docdir/$$file || :; \
	  fi; \
	done; \
	if ! test -d $(docdir)/other; then mkdir $(docdir)/other; fi;\
	for file in $(WEB_BIN); do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$docdir/other/$$file; \
	  else \
	    test -f $$docdir/other/$$file \
	    || ln $$here/$$file $$docdir/other/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$docdir/other/$$file || :; \
	  fi; \
	done

index.html: index.html.in $(WEBDOC)
	@if test "x$$BASE_URL" = "x"; then \
	echo '**********************************************'; \
	echo '** WARNING: BASE_URL not specified or empty **'; \
	echo '**********************************************'; \
	fi
	@echo "s^@BASE_URL@^$$BASE_URL^;" > .webdoc
	@echo "s/@DATE@/`date`/;" >> .webdoc
	@echo "s/@UPDATED@/`date +'%B, %d'`/;" >> .webdoc
	@for file in radius.info.tar.gz radius.dvi.gz radius.ps.gz radius.texi.tar.gz radius.text html_mono/radius.html; \
	do\
		ls -sk $$file; \
	done |\
         $(AWK) '{ gsub("\\.", "_", $$2); \
                   if (match($$2,"/")) \
                       $$2=substr($$2,RSTART+1); \
                   print "s/@" toupper(substr($$2,8)) "_SIZE@/" $$1 "/;" }' >> .webdoc
	sed -f .webdoc index.html.in > index.html
	rm .webdoc

webdocname=$(PACKAGE)-$(VERSION)-doc

webdoc: $(WEBDOC) index.html
	$(MAKE) docdir=$(top_builddir)/$(webdocname) docdir
	cd $(top_builddir) &&\
	tar cfz $(webdocname).tar.gz $(webdocname) &&\
	rm -r $(webdocname)

CLEANFILES=*.text *.html html_node/* html_chapter/* html_mono/* *.gz index.html
endif

