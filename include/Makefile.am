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

if MAINTAINER_MODE

all: raddict.h radmibs.h

raddict.h: ../raddb/dictionary
	$(AWK) -f ../scripts/dict.awk ../raddb/dictionary > raddict.h

radmibs.h: ../mibs/radmibs.h.in
	$(AWK) -f ../scripts/mksnmp-h.awk ../mibs/radmibs.h.in > radmibs.h

lint:;

endif
