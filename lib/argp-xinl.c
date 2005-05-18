/* Real definitions for extern inline functions in argp.h
   Copyright (C) 1997, 1998, 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Miles Bader <miles@gnu.ai.mit.edu>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.
   If not, write to the Free Software Foundation, Inc., 51 Franklin
   Street, Fifth Floor, Boston, MA 02110-1301 USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef __USE_EXTERN_INLINES
# define __USE_EXTERN_INLINES   1
#endif
#define ARGP_EI
#undef __OPTIMIZE__
#define __OPTIMIZE__
#include "argp.h"

/* Add weak aliases.  */
#if _LIBC - 0 && defined (weak_alias)

weak_alias (__argp_usage, argp_usage)
weak_alias (__option_is_short, _option_is_short)
weak_alias (__option_is_end, _option_is_end)

#endif
