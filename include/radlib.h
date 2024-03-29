/* This file is part of GNU Radius.
   Copyright (C) 2004, 2007, 2010, 2013 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. */

#include <radius/radius.h>
#include <sysdep.h>
#include <radius/mem.h>
#include <radius/list.h>
#include <radius/envar.h>
#include <radius/radpaths.h>
#include <radius/radutmp.h>
#include <radius/symtab.h>
#include <radius/argcv.h>
#include <radius/debug.h>
#include <pwd.h>

/* Internationalization support */
#include <gettext.h>
#define _(s) dgettext(PACKAGE, s)
#define N_(s) gettext_noop(s)

