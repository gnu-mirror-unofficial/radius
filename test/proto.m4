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
if ! test -d _FULL_PATH/$1; then mkdir _FULL_PATH/$1; else rm -f _FULL_PATH/$1/*; fi])

define([_print_zero],[ifelse($1,0,,0[_print_zero(decr($1))])])
define([_fmtnum],[_print_zero(eval($2-len($1)))$1])

dnl ***
dnl FILENAME(NAME,NUM,SUFFIX)
define([FILENAME],[_FULL_PATH/_TOOLDIR/[]_fmtnum(_SEQ_NUM,3)[]$1.$3])

dnl ***
dnl _GENTEXT(NAME,GENERIC[,NAME,GENERIC...])
define([_GENTEXT],[ifelse($1,,,_SUITEDIR,[$1],[$2],
[_GENTEXT(shift(shift($@)))])])

define([GENSEQUENCE],[_BEGIN_SEQUENCE($1,$2)
_GENTEXT(shift(shift($@)))
_END_SEQUENCE])

dnl ***
dnl SEQUENCE(NAME,COMMENT,tests...)
define([SEQUENCE],[_BEGIN_SEQUENCE($1,$2)
$3
_END_SEQUENCE])


divert[]dnl
