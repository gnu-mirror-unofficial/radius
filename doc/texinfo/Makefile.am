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
 config.texi\
 configure.texi\
 debug.texi\
 intro.texi\
 invoke.texi\
 logging.texi\
 naming.texi\
 operation.texi\
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

if MAINTAINER_MODE
TEXI2HTML=$(top_srcdir)/scripts/texi2html

radius.html: radius.texi $(radius_TEXINFOS)
	$(TEXI2HTML) -menu -monolithic radius.texi
endif
