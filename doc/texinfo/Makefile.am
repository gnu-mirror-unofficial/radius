# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2005,
# 2007 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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

EXTRA_DIST = gendocs_template

clean-local:
	rm -rf manual

# The rendering level is one of PUBLISH, DISTRIB or PROOF.
# Just call `make RENDITION=PROOF [target]' if you want PROOF rendition.
RENDITION = DISTRIB

MAKEINFOFLAGS=-D$(RENDITION)

GENDOCS=gendocs.sh

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -E

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/scripts:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t @finalout" \
	$(GENDOCS) $(PACKAGE) '$(PACKAGE_NAME) manual'

