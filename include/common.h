/* This file is part of GNU Radius.
   Copyright (C) 2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#include <radius/radius.h>
#include <sysdep.h>
#include <radius/mem.h>
#include <radius/list.h>
#include <radius/envar.h>
#include <radius/radpaths.h>
#include <radius/radutmp.h>
#include <radius/symtab.h>
#include <radius/argcv.h>
#include <pwd.h>

#define obstack_chunk_alloc grad_emalloc
#define obstack_chunk_free grad_free
#include <obstack.h>

#ifdef WITH_INCLUDED_REGEX
# include <../lib/rx.h>
#else
# include <regex.h>
#endif

/* Internationalization support */
#include <gettext.h>
#define _(s) gettext(s)
#define N_(s) gettext_noop(s)

typedef grad_uint32_t grad_counter_t;

