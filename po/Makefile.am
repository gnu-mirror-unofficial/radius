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

CATOBJEXT  = @CATOBJEXT@
INSTOBJEXT = @INSTOBJEXT@
GMSGFMT    = @GMSGFMT@
MSGFMT     = @MSGFMT@
#EXTRA_DIST = no.po

#LANGUAGES  = @LANGUAGES@
LANGUAGES  = 

localedir  = $(datadir)/locale
gnulocaledir = $(prefix)/share/locale

all-local: all-@USE_NLS@
all-no:
all-yes: $(LANGUAGES)
all-languages: 
#no: no.mo no.gmo

install-data-local: install-data-@USE_NLS@
install-data-no: 
install-data-yes: all
	if test -r "$(MKINSTALLDIRS)"; then \
	  $(MKINSTALLDIRS) $(datadir); \
	else \
	  $(SHELL) $(top_srcdir)/mkinstalldirs $(datadir); \
	fi
	@catalogs='$(LANGUAGES)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  case "$$cat" in \
	    *.gmo) destdir=$(gnulocaledir);; \
	    *)     destdir=$(localedir);; \
	  esac; \
	  lang=`echo $$cat | sed 's/\$(CATOBJEXT)$$//'`; \
	  dir=$$destdir/$$lang/LC_MESSAGES; \
	  if test -r "$(MKINSTALLDIRS)"; then \
	    $(MKINSTALLDIRS) $$dir; \
	  else \
	    $(SHELL) $(top_srcdir)/mkinstalldirs $$dir; \
	  fi; \
	  if test -r $$cat; then \
	    $(INSTALL_DATA) $$cat $$dir/$(PACKAGE)$(INSTOBJEXT); \
	    echo "installing $$cat as $$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	  else \
	    $(INSTALL_DATA) $(srcdir)/$$cat $$dir/$(PACKAGE)$(INSTOBJEXT); \
	    echo "installing $(srcdir)/$$cat as" \
		 "$$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	  fi; \
	  if test -r $$cat$(INSTOBJEXT); then \
	    $(INSTALL_DATA) $$cat$(INSTOBJEXT) \
                            $$dir/$(PACKAGE)$(INSTOBJEXT); \
	    echo "installing $$cat$(INSTOBJEXT) as $$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	  else \
	    if test -r $(srcdir)/$$cat$(INSTOBJEXT) ; then \
	      $(INSTALL_DATA) $(srcdir)/$$cat$(INSTOBJEXT) \
		$$dir/$(PACKAGE)$(INSTOBJEXT).m; \
	      echo "installing $(srcdir)/$$cat$(INSTOBJEXT) as" \
		   "$$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	    else \
	      true; \
	    fi; \
	  fi; \
	done



SUFFIXES=.c .o .po .pox .gmo .mo .msg .cat

.po.mo:
	$(MSGFMT) -o $@ $<

.po.gmo:
	file=$(srcdir)/`echo $* | sed 's,.*/,,'`.gmo \
	 && rm -f $$file && $(GMSGFMT) -o $$file $<

if MAINTAINER_MODE

endif

