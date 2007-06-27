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

#ifndef _gnu_radius_symtab_h
#define _gnu_radius_symtab_h

typedef struct symbol grad_symbol_t;
struct symbol {
        grad_symbol_t *next;
        char *name;
} ;

typedef struct {
        int elsize;
        int elcnt;
        int hash_num;
        grad_symbol_t **sym;
        int (*elfree)();
} grad_symtab_t;

grad_symtab_t * grad_symtab_create(unsigned esize, int (*)());
void grad_symtab_free(grad_symtab_t **symtab);
void grad_symtab_clear(grad_symtab_t *symtab);

void *grad_sym_install(grad_symtab_t *symtab, const char *name);
void *grad_sym_lookup(grad_symtab_t *symtab, const char *name);
void *grad_sym_lookup_or_install(grad_symtab_t *symtab,
				 const char *name, int install);
void *grad_sym_next(grad_symbol_t *sym);

void grad_symtab_iterate(grad_symtab_t *symtab,
			 int (*fn)(void *, grad_symbol_t *),
			 void *closure);

int grad_symtab_delete(grad_symtab_t *symtab, grad_symbol_t *sym);

void     grad_sym_free(grad_symbol_t *);

#endif /* !_gnu_radius_symtab_h */
