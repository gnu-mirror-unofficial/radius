/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* $Id$ */
#ifndef __mem_h
#define __mem_h

#define MEM_PAGESIZE 4096
#ifndef MINSTRSIZE
# define MINSTRSIZE  32
#endif

typedef unsigned count_t;
typedef double Align_t;
struct mallocstat {
        int count;
        unsigned size;
};
extern struct mallocstat mallocstat;

typedef struct {
        unsigned class_cnt;
        unsigned bucket_cnt;
        unsigned bytes_allocated;
        unsigned bytes_used;
} MEM_STAT;

typedef struct {
        int         index;
        int         cont;            /* Allow contiguous allocation */
        size_t      elsize;          /* Size of an element */
        count_t     elcnt;           /* Number of elements per bucket */
        count_t     allocated_cnt;   /* Number of allocated elements */
        count_t     bucket_cnt;      /* Number of buckets */
} CLASS_STAT;


void *mem_alloc(size_t size);
void mem_free(void *ptr);
void *mem_calloc(count_t count, size_t size);
void mem_cfree(void *ptr, count_t count);

void *radxmalloc(size_t);
void *emalloc(size_t);
void *radxrealloc(void *, size_t);
void *erealloc(void *, size_t);
void efree(void *);
char *estrdup(char *);

char *string_alloc(size_t length);
char *string_create(char *str);
char *string_dup(char *str);
void string_free(char *str);
char *string_replace(char **str, char *value);

void mem_get_stat(MEM_STAT *stat);
int mem_stat_enumerate(int (*fun)(), void *closure);

#endif
