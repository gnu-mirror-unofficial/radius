# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

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
 fdl.texi\
 gradient.texi\
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
 radtest.texi\
 radscm.texi\
 radwho.texi\
 radzap.texi\
 rendition.texi\
 version.texi

EXTRA_DIST = index.html.in

CLEANFILES=tmp-* *.tmp *.ats *.cps *.exs *.fns *.kws *.pgs \
 *.text *.html 

PROJECT=$(PACKAGE_TARNAME)
RENDITION=DISTRIB
MAKEINFOFLAGS=-D$(RENDITION)

tmp-$(PROJECT).texi: $(info_TEXINFOS) $(radius_TEXINFOS)
	$(MAKEINFO) -D$(RENDITION) -Etmp-$(PROJECT).tmp -otmp-$(PROJECT).info \
	 -I$(srcdir) $(PROJECT).texi
	rm -f tmp-$(PROJECT).sed tmp-$(PROJECT).info*
	echo '' > tmp-$(PROJECT).sed
	test $(RENDITION) = DISTRIB \
	  || echo >>tmp-$(PROJECT).sed 's/^@set DISTRIB/@set $(RENDITION)/'
	sed -f tmp-$(PROJECT).sed tmp-$(PROJECT).tmp > tmp-$(PROJECT).texi
	rm -f tmp-$(PROJECT).sed tmp-$(PROJECT).tmp

$(PROJECT).dvi: tmp-$(PROJECT).texi
	TEXINPUTS=$(top_srcdir)/scripts:$$TEXINPUTS \
	 MAKEINFO='$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir)' \
	 $(TEXI2DVI) tmp-$(PROJECT).texi
	mv tmp-$(PROJECT).dvi $@


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

radius.pdf.gz: radius.pdf
	gzip -c radius.pdf > radius.pdf.gz

radius.texi.tar.gz:
	tar cfz radius.texi.tar.gz *.texi

WEB_HTML=\
 html_mono\
 html_node\
 html_chapter

WEB_BIN=\
 radius.info.tar.gz\
 radius.dvi.gz\
 radius.pdf.gz\
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

