/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
/* $Id$ */

typedef struct symbol Symbol;
struct symbol {
	Symbol *next;
	char *name;
} ;

typedef struct {
	int elsize;
	int hashsize;
	Symbol **sym;
	int (*elfree)();
} Symtab;

Symtab * symtab_create(unsigned esize, unsigned hsize, int (*)());
void symtab_free(Symtab *symtab);

Symbol * sym_install(Symtab *symtab, char *name);
Symbol * sym_lookup(Symtab *symtab, char *name);
Symbol * sym_next(Symbol *sym);

Symbol * alloc_sym(char *, unsigned);
void     sym_free(Symbol *);

