# This file is part of GNU Radius.
# Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.
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
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

pamdir=@PAMDIR@
pam_LTLIBRARIES = @BUILD_PAM_RADIUS_LA@
EXTRA_LTLIBRARIES = pam_radius.la
pam_radius_la_SOURCES = pam_radius.c
pam_radius_la_LIBADD = -lpam @LIBGNURADIUS@ @LTLIBINTL@
INCLUDES = @RADIUS_INCLUDE_PATH@ 
AM_CPPFLAGS=@PATHFLAGS@

pam_radius_la_LDFLAGS = -module -avoid-version -no-undefined -rpath $(pamdir) \
 -Wl,-Bsymbolic

