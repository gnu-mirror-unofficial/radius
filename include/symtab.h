/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* $Id$ */

#ifndef __symtab_h
#define __symtab_h

typedef struct symbol Symbol;
struct symbol {
        Symbol *next;
        char *name;
} ;

typedef struct {
        int elsize;
        int elcnt;
        int hash_num;
        Symbol **sym;
        int (*elfree)();
} Symtab;

Symtab * symtab_create(unsigned esize, int (*)());
void symtab_free(Symtab **symtab);
void symtab_clear(Symtab *symtab);

void *sym_install(Symtab *symtab, char *name);
void *sym_lookup(Symtab *symtab, char *name);
void *sym_lookup_or_install(Symtab *symtab, char *name, int install);
void *sym_next(Symbol *sym);
void symtab_iterate(Symtab *symtab, int (*fn)(), void *closure);
int symtab_delete(Symtab *symtab, Symbol *sym);

Symbol * alloc_sym(char *, unsigned);
void     sym_free(Symbol *);

#endif
