# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2003,2004 Free Software Foundation, Inc.
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

phpmoddir=@PHPMODDIR@
phpmod_LTLIBRARIES = @BUILD_MOD_RADIUS_LA@
EXTRA_LTLIBRARIES = mod_radius.la
mod_radius_la_SOURCES = mod_radius.c
mod_radius_la_LIBADD = @LIBGNURADIUS@ @LTLIBINTL@
INCLUDES = @RADIUS_INCLUDE_PATH@ @PHP_INCLUDES@
AM_CPPFLAGS=-DCOMPILE_DL_FIRST_MODULE=1

mod_radius_la_LDFLAGS = -module -avoid-version -rpath $(phpmoddir) 

EXTRA_DIST = README 
