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
#ifndef __mem_h
#define __mem_h

#define MEM_PAGESIZE 4096
#ifndef MINSTRSIZE
# define MINSTRSIZE  32
#endif

typedef unsigned count_t;

struct mallocstat {
	int count;
	unsigned size;
};
extern struct mallocstat mallocstat;

void *alloc_entry(size_t size);
void free_entry(void *ptr);
void *calloc_entry(count_t count, size_t size);
void cfree_entry(void *ptr, count_t count);

void *xmalloc(size_t);
void *emalloc(size_t);
void efree(void *);
char *estrdup(char *);

char *alloc_string(size_t length);
char *make_string(char *str);
char *dup_string(char *str);
void free_string(char *str);
char *replace_string(char **str, char *strvalue);

void meminfo(int (*report)());
		
#endif
