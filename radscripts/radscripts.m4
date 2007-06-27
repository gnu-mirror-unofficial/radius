divert(-1)dnl
dnl This file is part of GNU Radius.
dnl Copyright (C) 2004, 2007 Free Software Foundation, Inc.
dnl
dnl Written by Sergey Poznyakoff
dnl 
dnl GNU Radius is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl 
dnl GNU Radius is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with GNU Radius; if not, write to the Free Software Foundation,
dnl Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  
changequote([,])
changecom(%%)
define([SHIFT],[[shift]])
define([TEST],[[ [ $1 ] ]])
define([OPT_HELP],[-h|--h|--he|--hel|--help])
define([OPT_VERSION],[--v|--ve|--ver|--vers|--versi|--versio|--version])
define([NOEDIT],[ifdef([__file__],[Generated from __file__],[This script is generated authomatically. Please do not edit.])])
define([ARITH],[$(($1))])
dnl For really old shells replace this with: define([ARITH],[`expr '$1'`])
divert(0)dnl
