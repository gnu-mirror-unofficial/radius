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

static char rcsid[] = 
"$Id$";

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sysdep.h>
#include <symtab.h>
#include <mem.h>

#define DEFAULT_HASHSIZE 1033


Symbol * alloc_sym(char *, unsigned);
static unsigned int hashval(unsigned char *s, unsigned bias);

Symtab *
symtab_create(esize, hsize, elfree)
	unsigned esize;
	unsigned hsize;
	int (*elfree)();
{
	Symtab *symtab;
	
	if (hsize == 0)
		hsize = DEFAULT_HASHSIZE;
	symtab = emalloc(sizeof(*symtab) + hsize * esize);
	symtab->elsize = esize;
	symtab->hashsize = hsize;
	symtab->elfree = elfree;
	symtab->sym = (Symbol**)(symtab + 1);
	return symtab;
}

unsigned int
hashval(s, bias)
	unsigned char *s;
	unsigned bias;
{
	unsigned h = 0;

	for (; *s; s++) {
		h <<= 1;
		h ^= *s;
	}
	return h % bias;
}

Symbol *
sym_install(symtab, name)
	Symtab *symtab;
	char *name;
{
	Symbol *sp;
	unsigned int h = hashval(name, symtab->hashsize);

	sp = alloc_sym(name, symtab->elsize);
	sp->next = symtab->sym[h];
	symtab->sym[h] = sp;
	return sp;
}

Symbol *
sym_lookup(symtab, name)
	Symtab *symtab;
	char *name;
{
	Symbol *sp;
	unsigned h = hashval(name, symtab->hashsize);

	for (sp = symtab->sym[h]; sp; sp = sp->next) {
		if (strcmp(sp->name, name) == 0)
			return sp;
	}
	return NULL;
}

Symbol *
sym_next(sym)
	Symbol *sym;
{
	char *name = sym->name;
	for (sym = sym->next; sym; sym = sym->next) {
		if (strcmp(sym->name, name) == 0)
			return sym;
	}
	return NULL;
}

Symbol *
alloc_sym(s, size)
	char *s;
	unsigned size;
{
	Symbol *ptr;
	ptr = alloc_entry(size);
	ptr->name = estrdup(s);
	return ptr;
}

void
sym_free(sp)
	Symbol *sp;
{
	efree(sp->name);
	free_entry(sp);
}

void
symtab_free(symtab)
	Symtab *symtab;
{
	int i;
	Symbol *sp, *next;

	if (!symtab)
		return;
	
	for (i = 0; i < symtab->hashsize; i++) {
		for (sp = symtab->sym[i]; sp; sp = next) {
			next = sp->next;
			if (symtab->elfree)
				symtab->elfree(sp);
			sym_free(sp);
		}
		symtab->sym[i] = NULL;
	}
}


