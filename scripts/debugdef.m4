divert(-1) -*- m4 -*-
# This file is part of GNU Radius
# Copyright (C) 2007 Free Software Foundation
#
# Written by Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA 

changequote([<,>])
changecom(/*,*/)

define([<__arglist>],[<dnl
ifelse($1,$2,x$1,
[<x$1, __arglist(incr($1), $2)>])>])

define([<MKDEBUG>],[<
[<#if RADIUS_DEBUG
#define __grad_debug>]$1[<(fmt, >]__arglist(1,$1))  \[<
 do {                                                                         \
   if (grad_source_info_option)                                               \
    grad_log(GRAD_LOG_DEBUG, "%s:%lu:%s: " fmt, __FILE__, __LINE__, __FUNCTION__, >]dnl
__arglist(1,$1)[<); \
   else                                                                       \
    grad_log(GRAD_LOG_DEBUG, fmt,>]dnl
__arglist(1,$1)[<);\
 } while (0)                                                                  
#define GRAD_DEBUG>]$1[<(lev, fmt, >]__arglist(1,$1)[<) \
 do { if (GRAD_DEBUG_LEVEL(lev)) __grad_debug>]$1[<(fmt, >]__arglist(1,$1)[<); } while(0)
#else
# define GRAD_DEBUG>]$1[<(lev, fmt, >]__arglist(1,$1)[<)>]
#endif
>])

divert(0)dnl
/* -*- buffer-read-only: t -*- vi: set ro:
   THIS FILE IS GENERATED AUTOMATICALLY.  PLEASE DO NOT EDIT.
*/
