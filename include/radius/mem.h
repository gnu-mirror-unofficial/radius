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

/* $Id$ */
#ifndef _gnu_radius_mem_h
#define _gnu_radius_mem_h

typedef unsigned count_t;
typedef double Align_t;
struct mallocstat {
        int count;
        unsigned size;
};
extern struct mallocstat mallocstat;

void *grad_malloc(size_t);
void *grad_emalloc(size_t);
void *grad_realloc(void *, size_t);
void *grad_erealloc(void *, size_t);
void grad_free(void *);
void grad_destroy(void **);
char *grad_estrdup(const char *);

char *grad_string_replace(char **str, const char *value);

#endif
