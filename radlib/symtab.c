/* This file is part of GNU RADIUS.
 * Copyright (C) 2000,2001, Sergey Poznyakoff
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

#ifndef lint
static char rcsid[] = 
"@(#) $Id$";
#endif

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

/* Hash sizes. These are prime numbers, the distance between each
   pair of them grows exponentially, starting from 64.
   Hopefully no one will need more than 1048661 hash entries, and even if
   someone will, it is easy enough to add more numbers to the sequence. */
static size_t hash_size[] = {
	1,2,3,4,5,6,
	37,    101,    229,    487,    1009, 2039, 4091, 8191, 16411, 32797,
     65579, 131129, 262217, 524369, 1048661
};

/* Maximum number of re-hashes: */
static int max_rehash = sizeof (hash_size) / sizeof (hash_size[0]);


Symbol * alloc_sym(char *, unsigned);
static unsigned int hashval(unsigned char *s, unsigned bias);
static void _sym_add(Symtab *symtab, unsigned h, Symbol *sp);

Symtab *
symtab_create(esize, elfree)
	unsigned esize;
	int (*elfree)();
{
	Symtab *symtab;
	
	symtab = emalloc(sizeof(*symtab));
	symtab->elsize = esize;
	symtab->elcnt = 0;
	symtab->hash_num = -1;
	symtab->elfree = elfree;
	symtab->sym = NULL;
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

void
_sym_add(symtab, h, sp)
	Symtab *symtab;
	unsigned h;
	Symbol *sp;
{
	sp->next = NULL;
	if (symtab->sym[h]) {
		Symbol *prev;
		for (prev = symtab->sym[h]; prev->next; prev = prev->next)
			;
		prev->next = sp;
	} else
		symtab->sym[h] = sp;
}

int
symtab_rehash(symtab)
	Symtab *symtab;
{
	Symbol **old_table = symtab->sym;
	int i;
  
	if (++symtab->hash_num >= max_rehash) {
		/*FIXME: report error*/
		abort();
	}

	symtab->sym = emalloc(hash_size[symtab->hash_num] * symtab->elsize);

	if (old_table) {
		size_t old_size = hash_size[symtab->hash_num-1];
		
		for (i = 0; i < old_size; i++) {
			Symbol *sym, *next;
			
			sym = old_table[i];
			while (sym) {
				unsigned int h;

				next = sym->next;

				h = hashval((unsigned char *) sym->name,
					    hash_size[symtab->hash_num]);
				_sym_add(symtab, h, sym);
				sym = next;
			}
		}
		efree (old_table);
	}
	return 0;
}

void *
sym_lookup_or_install(symtab, name, install)
	Symtab *symtab;
	char *name;
	int install;
{
	if (symtab->sym) {
		Symbol *sp;
		unsigned h;

		h = hashval((unsigned char *)name,
			    hash_size[symtab->hash_num]);

		for (sp = symtab->sym[h]; sp; sp = sp->next) {
			if (strcmp(sp->name, name) == 0)
				return sp;
		}
	}
	
	if (install)
		return sym_install(symtab, name);
		
	return NULL;
}

void *
sym_install(symtab, name)
	Symtab *symtab;
	char *name;
{
	Symbol *sp;
	unsigned int h;

	if (!symtab->sym
	    || 10 * symtab->elcnt / hash_size[symtab->hash_num] > 20/3)
		symtab_rehash(symtab);
	
	h = hashval((unsigned char *)name, hash_size[symtab->hash_num]);

	sp = alloc_sym(name, symtab->elsize);
	_sym_add(symtab, h, sp);
	symtab->elcnt++;
	return sp;
}

void *
sym_lookup(symtab, name)
	Symtab *symtab;
	char *name;
{
	return sym_lookup_or_install(symtab, name, 0);
}

void *
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

/*
 * Delete the symbol `sym' from symtab.
 */
int
symtab_delete(symtab, sym)
	Symtab *symtab;
	Symbol *sym;
{
	Symbol *sp, *prev;
	unsigned h;

	if (!symtab->sym)
		return 1;

	h = hashval((unsigned char *)sym->name, hash_size[symtab->hash_num]);

	/*
	 * Lookup the symbol
	 */
	sp = symtab->sym[h];
	prev = NULL;
	while (sp) {
		if (sp == sym) 
			break;
		prev = sp;
		sp = sp->next;
	}

	if (!sp)
		return -1;

	/*
	 * Prev points to the previous symbol (if any).
	 * Remove our symbol from the list.
	 */
	if (prev)
		prev->next = sp->next;
	else
		symtab->sym[h] = sp->next;

	/*
	 * Free associated memory
	 */
	if (symtab->elfree)
		symtab->elfree(sp);
	sym_free(sp);
	symtab->elcnt--;
	return 0;
}

void
sym_free(sp)
	Symbol *sp;
{
	efree(sp->name);
	free_entry(sp);
}

void
symtab_clear(symtab)
	Symtab *symtab;
{
	int i;
	Symbol *sp, *next;

	if (!symtab || !symtab->sym)
		return;
	
	for (i = 0; i < hash_size[symtab->hash_num]; i++) {
		for (sp = symtab->sym[i]; sp; sp = next) {
			next = sp->next;
			if (symtab->elfree)
				symtab->elfree(sp);
			sym_free(sp);
		}
		symtab->sym[i] = NULL;
	}
	symtab->elcnt = 0;
}

void
symtab_free(symtab)
	Symtab **symtab;
{
	symtab_clear(*symtab);
	efree((*symtab)->sym);
	efree(*symtab);
	*symtab = NULL;
}

void
symtab_iterate(symtab, fn, closure)
	Symtab *symtab;
	int (*fn)();
	void *closure;
{
	int i;
	Symbol *sym, *next;
	
	for (i = 0; i < hash_size[symtab->hash_num]; i++) {
		sym = symtab->sym[i];
		while (sym) {
			next = sym->next;
			if ((*fn)(closure, sym))
				break;
			sym = next;
		}
	}
}


