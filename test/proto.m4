divert(-1)
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001 Sergey Poznyakoff
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# $Id$
changequote([,])

define([_FULL_PATH],[BUILDDIR/test/_SUITEDIR])

dnl ***
dnl TOOLDIR(NAME, START-ARG, SEQ...)
define([TOOLDIR],[define([_TOOLDIR],$1)
define([_SEQ_NUM],0)
if ! test -d _FULL_PATH/$1; then mkdir _FULL_PATH/$1; fi])

dnl ***
define([BEGIN],[SEQUENCE(Start,,default_radiusd_start $1)])

define([END],[SEQUENCE(Stop,,radius_exit)])

dnl ***
dnl FILENAME(NAME,NUM,SUFFIX)
define([FILENAME],[_FULL_PATH/_TOOLDIR/[]eval(_SEQ_NUM,10,$2)[]$1.$3])
divert[]dnl
