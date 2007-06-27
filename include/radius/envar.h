/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef _gnu_radius_envar_h
#define _gnu_radius_envar_h

#include <radius/list.h>

typedef grad_list_t grad_envar_t;

grad_envar_t *grad_envar_parse(char *str);
grad_envar_t *grad_envar_parse_argcv(int argc, char **argv);
void grad_envar_free_list(grad_envar_t **);
char *grad_envar_lookup(grad_envar_t *, char *);
char *grad_envar_lookup_str(grad_envar_t *env, char *name, char *defval);
int grad_envar_lookup_int(grad_envar_t *env, char *name, int defval);
grad_envar_t *grad_envar_merge_lists(grad_envar_t *prim, grad_envar_t *sec);

#endif
