# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Free Software Foundation
# Written by Sergey Poznyakoff
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
 comp.texi\
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

EXTRA_DIST = index.html.in

CLEANFILES=*.tmp *.ats *.cps *.exs *.fns *.kws *.pgs \
 *.text *.html 

if MAINTAINER_MODE
BASE_URL="http://www.gnu.org/software/radius/manual/"
TEXI2HTML=${SHELL} `cd $(top_srcdir); pwd`/scripts/missing --run texi2html
INFO=${SHELL} `cd $(top_srcdir); pwd`/scripts/missing --run info
DVIPDF=${SHELL} `cd $(top_srcdir); pwd`/scripts/missing --run dvipdf

clean-local:
	rm -rf $(WEB_BIN) $(WEB_HTML) index.html

html: html_mono html_node html_chapter

html_node:
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_node; then mkdir html_node; fi; \
	cd html_node; \
	$$texi2html -menu -split_node ../radius.texi

html_chapter:
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_chapter; then mkdir html_chapter; fi; \
	cd html_chapter; \
	$$texi2html -menu -split_chapter ../radius.texi

html_mono:
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_mono; then mkdir html_mono; fi; \
	cd html_mono; \
	$$texi2html -menu -monolithic ../radius.texi

ps: radius.ps

radius.ps: radius.dvi
	$(DVIPS) -oradius.ps radius.dvi

# Override the default rule. The texinfo <= 4.5 is unable to cope with
# radius docs.
radius.pdf: radius.dvi
	$(DVIPDF) radius.dvi

text: radius.text

radius.text: radius.info
	$(INFO) --node=Top --subnodes --out radius.text -f radius.info

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

webdocdir: $(WEBDOC) index.html
	if ! test -d $(WEBDOCDIR); then mkdir $(WEBDOCDIR); fi; \
	here=`cd $(srcdir) && pwd`; \
	webdocdir=`cd $(WEBDOCDIR) && pwd`; \
	for file in $(WEB_HTML) index.html; do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$webdocdir/$$file; \
	  else \
	    test -f $$webdocdir/$$file \
	    || ln $$here/$$file $$webdocdir/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$webdocdir/$$file || :; \
	  fi; \
	done; \
	if ! test -d $(WEBDOCDIR)/other; then mkdir $(WEBDOCDIR)/other; fi;\
	for file in $(WEB_BIN); do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$webdocdir/other/$$file; \
	  else \
	    test -f $$webdocdir/other/$$file \
	    || ln $$here/$$file $$webdocdir/other/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$webdocdir/other/$$file || :; \
	  fi; \
	done

index.html: index.html.in $(WEBDOC)
	@echo "s^%BASE_URL%^$(BASE_URL)^;" > .webdoc
	@echo "s/%DATE%/`date`/;" >> .webdoc
	@echo "s/%UPDATED%/`date +'%B, %d'`/;" >> .webdoc
	@echo "s/%PACKAGE_NAME%/$(PACKAGE_NAME)/" >> .webdoc
	@echo "s/%PACKAGE%/$(PACKAGE)/" >> .webdoc
	@echo "s/%VERSION%/$(VERSION)/" >> .webdoc
	@for file in `sed -n 's,.*"other/%PACKAGE%\(.*\)".*,$(PACKAGE)\1,pg;s,.*"\(.*\)%PACKAGE%\(.*\)".*,\1$(PACKAGE)\2,pg' index.html.in`; \
	do\
		ls -sk $$file; \
	done |\
         $(AWK) -vPACKAGE=$(PACKAGE) \
                'BEGIN { len = length(PACKAGE) } \
                 { gsub("\\.", "_", $$2); \
                   if (match($$2,"/")) \
                       $$2=substr($$2,RSTART+1); \
                   print "s/%" toupper(substr($$2,len+2)) "_SIZE%/" $$1 "/;" }' >> .webdoc
	sed -f .webdoc index.html.in > index.html
	rm -f .webdoc

webdocname=$(PACKAGE)-$(VERSION)-doc
WEBDOCDIR=$(webdocname)

webdoc: $(WEBDOC) index.html
	$(MAKE) WEBDOCDIR=$(top_builddir)/doc/texinfo/$(webdocname) webdocdir
	cd $(top_builddir)/doc/texinfo &&\
	tar cfz $(webdocname).tar.gz $(webdocname) &&\
	rm -r $(webdocname)

## End of webdoc
endif

