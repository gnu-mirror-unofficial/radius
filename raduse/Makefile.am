# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003,2013 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

bin_PROGRAMS    = raduse
raduse_SOURCES = raduse.c session.c stat.c raduse.h
raduse_LDADD   = ../snmplib/libradsnmp.a ../lib/liblog.la ../lib/librad.la ../lib/libdebug.la @LIBINTL@
AM_CPPFLAGS    = @RADIUS_INCLUDE_PATH@

