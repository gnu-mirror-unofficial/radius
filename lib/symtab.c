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
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sysdep.h>
#include <radius/symtab.h>
#include <radius/mem.h>

/* Hash sizes. These are prime numbers, the distance between each
   pair of them grows exponentially, starting from 64.
   Hopefully no one will need more than 1048661 hash entries, and even if
   someone will, it is easy enough to add more numbers to the sequence. */
static size_t hash_size[] = {
        37,    101,    229,    487,    1009, 2039, 4091, 8191, 16411, 32797,
     65579, 131129, 262217, 524369, 1048661
};

/* Maximum number of re-hashes: */
static int max_rehash = sizeof (hash_size) / sizeof (hash_size[0]);

grad_symbol_t *
alloc_sym(const char *s, unsigned size)
{
        grad_symbol_t *ptr;
        ptr = grad_emalloc(size);
        ptr->name = grad_estrdup(s);
        return ptr;
}

static unsigned int
hashval(const unsigned char *s, unsigned bias)
{
        unsigned h = 0;

        for (; *s; s++) {
                h <<= 1;
                h ^= *s;
        }
        return h % bias;
}

static void
_sym_add(grad_symtab_t *symtab, unsigned h, grad_symbol_t *sp)
{
        sp->next = NULL;
        if (symtab->sym[h]) {
                grad_symbol_t *prev;
                for (prev = symtab->sym[h]; prev->next; prev = prev->next)
                        ;
                prev->next = sp;
        } else
                symtab->sym[h] = sp;
}

grad_symtab_t *
grad_symtab_create(unsigned esize, int (*elfree)())
{
        grad_symtab_t *symtab;
        
        symtab = grad_emalloc(sizeof(*symtab));
        symtab->elsize = esize;
        symtab->elcnt = 0;
        symtab->hash_num = -1;
        symtab->elfree = elfree;
        symtab->sym = NULL;
        return symtab;
}

int
grad_symtab_rehash(grad_symtab_t *symtab)
{
        grad_symbol_t **old_table = symtab->sym;
        int i;
  
        if (++symtab->hash_num >= max_rehash) {
                /*FIXME: report error*/
                abort();
        }

        symtab->sym = grad_emalloc(hash_size[symtab->hash_num] * symtab->elsize);

        if (old_table) {
                size_t old_size = hash_size[symtab->hash_num-1];
                
                for (i = 0; i < old_size; i++) {
                        grad_symbol_t *sym, *next;
                        
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
                grad_free (old_table);
        }
        return 0;
}

void *
grad_sym_lookup_or_install(grad_symtab_t *symtab, const char *name,
			   int install)
{
        if (symtab->sym) {
                grad_symbol_t *sp;
                unsigned h;

                h = hashval((unsigned char *)name,
                            hash_size[symtab->hash_num]);
		
                for (sp = symtab->sym[h]; sp; sp = sp->next) {
                        if (strcmp(sp->name, name) == 0)
                                return sp;
                }
        }
        
        if (install)
                return grad_sym_install(symtab, name);
                
        return NULL;
}

void *
grad_sym_install(grad_symtab_t *symtab, const char *name)
{
        grad_symbol_t *sp;
        unsigned int h;

        if (!symtab->sym
            || 10 * symtab->elcnt / hash_size[symtab->hash_num] > 20/3)
                grad_symtab_rehash(symtab);
        
        h = hashval((unsigned char *)name, hash_size[symtab->hash_num]);

        sp = alloc_sym(name, symtab->elsize);
        _sym_add(symtab, h, sp);
        symtab->elcnt++;
        return sp;
}

void *
grad_sym_lookup(grad_symtab_t *symtab, const char *name)
{
        return grad_sym_lookup_or_install(symtab, name, 0);
}

void *
grad_sym_next(grad_symbol_t *sym)
{
        char *name = sym->name;
        for (sym = sym->next; sym; sym = sym->next) {
                if (strcmp(sym->name, name) == 0)
                        return sym;
        }
        return NULL;
}

/*
 * Delete the symbol `sym' from symtab.
 */
int
grad_symtab_delete(grad_symtab_t *symtab, grad_symbol_t *sym)
{
        grad_symbol_t *sp, *prev;
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
        grad_sym_free(sp);
        symtab->elcnt--;
        return 0;
}

void
grad_sym_free(grad_symbol_t *sp)
{
        grad_free(sp->name);
        grad_free(sp);
}

void
grad_symtab_clear(grad_symtab_t *symtab)
{
        int i;
        grad_symbol_t *sp, *next;

        if (!symtab || !symtab->sym)
                return;
        
        for (i = 0; i < hash_size[symtab->hash_num]; i++) {
                for (sp = symtab->sym[i]; sp; sp = next) {
                        next = sp->next;
                        if (symtab->elfree)
                                symtab->elfree(sp);
                        grad_sym_free(sp);
                }
                symtab->sym[i] = NULL;
        }
        symtab->elcnt = 0;
}

void
grad_symtab_free(grad_symtab_t **symtab)
{
	if (!symtab || !*symtab)
		return;
        grad_symtab_clear(*symtab);
        grad_free((*symtab)->sym);
        grad_free(*symtab);
        *symtab = NULL;
}

void
grad_symtab_iterate(grad_symtab_t *symtab,
		    int (*fn)(void *, grad_symbol_t *),
		    void *closure)
{
        int i;
        grad_symbol_t *sym, *next;

	if (!symtab->sym)
		return;
        for (i = 0; i < hash_size[symtab->hash_num]; i++) {
                sym = symtab->sym[i];
                while (sym) {
                        next = sym->next;
                        if ((*fn)(closure, sym))
                                return;
                        sym = next;
                }
        }
}


