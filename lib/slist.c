/* This file is part of GNU Radius.
   Copyright (C) 2007 Free Software Foundation, Inc.

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
#include <radlib.h>

struct grad_slist_bucket {
	struct grad_slist_bucket *next;
	char *buf;
	size_t level;
	size_t size;
};

struct grad_slist {
	struct grad_slist_bucket *head, *tail;
	struct grad_slist_bucket *free;
};

static struct grad_slist_bucket *
alloc_bucket(size_t size)
{
	struct grad_slist_bucket *p = grad_malloc(sizeof(*p) + size);
	p->buf = (char*)(p + 1);
	p->level = 0;
	p->size = size;
	p->next = NULL;
	return p;
}

static void
alloc_pool(grad_slist_t slist, size_t size)
{
	struct grad_slist_bucket *p = alloc_bucket(GRAD_SLIST_BUCKET_SIZE);
	if (slist->tail)
		slist->tail->next = p;
	else
		slist->head = p;
	slist->tail = p;
}

static size_t
copy_chars(grad_slist_t slist, char *str, size_t n)
{
	size_t rest;


	if (!slist->head || slist->tail->level == slist->tail->size)
		alloc_pool(slist, GRAD_SLIST_BUCKET_SIZE);
	rest = slist->tail->size - slist->tail->level;
	if (n > rest)
		n = rest;
	memcpy(slist->tail->buf + slist->tail->level, str, n);
	slist->tail->level += n;
	return n;
}

grad_slist_t 
grad_slist_create()
{
	grad_slist_t slist = grad_malloc(sizeof(*slist));
	slist->head = slist->tail = 0;
	return slist;
}

void
grad_slist_clear(grad_slist_t slist)
{
	if (slist->tail) {
		slist->tail->next = slist->free;
		slist->free = slist->head;
		slist->head = slist->tail = NULL;
	}
}	


void
grad_slist_free(grad_slist_t *slist)
{
	struct grad_slist_bucket *p;
	if (*slist) {
		grad_slist_clear(*slist);
		for (p = (*slist)->free; p; ) {
			struct grad_slist_bucket *next = p->next;
			grad_free(p);
			p = next;
		}
	}
	grad_free(*slist);
	*slist = NULL;
}

void
grad_slist_append(grad_slist_t slist, void *str, size_t n)
{
	char *ptr = str;
	while (n) {
		size_t s = copy_chars(slist, ptr, n);
		ptr += s;
		n -= s;
	}
}

void
grad_slist_append_char(grad_slist_t slist, char c)
{
	grad_slist_append(slist, &c, 1);
}	

size_t
grad_slist_size(grad_slist_t slist)
{
	size_t size = 0;
	struct grad_slist_bucket *p;
	for (p = slist->head; p; p = p->next)
		size += p->level;
	return size;
}

size_t
grad_slist_coalesce(grad_slist_t slist)
{
	size_t size;

	if (slist->head && slist->head->next == NULL)
		size = slist->head->level;
	else {
		struct grad_slist_bucket *bucket;
		struct grad_slist_bucket *p;

		size = grad_slist_size(slist);
	
		bucket = alloc_bucket(size);
		for (p = slist->head; p; ) {
			struct grad_slist_bucket *next = p->next;
			memcpy(bucket->buf + bucket->level, p->buf, p->level);
			bucket->level += p->level;
			grad_free(p);
			p = next;
		}
		slist->head = slist->tail = bucket;
	}
	return size;
}

void *
grad_slist_head(grad_slist_t slist, size_t *psize)
{
	if (psize) 
		*psize = slist->head ? slist->head->level : 0;
	return slist->head ? slist->head->buf : NULL;
}

void *
grad_slist_finish(grad_slist_t slist)
{
	grad_slist_coalesce(slist);
	grad_slist_clear(slist);
	return slist->free->buf;
}


#define to_num(c) \
  (isdigit(c) ? c - '0' : (isxdigit(c) ? toupper(c) - 'A' + 10 : 255 ))

void
grad_slist_grow_backslash_num(grad_slist_t slist, char *text, char **pend,
			      int len, int base)
{
	int i;
	int val = 0;
	char *start = text;
	
	if (text[0] == '\\') {
		text++;
		if (base == 16)
			text++;
	}
	
	for (i = 0; i < len; i++) {
		int n = (unsigned char)text[i];
		if (n > 127 || (n = to_num(n)) >= base)
			break;
		val = val*base + n;
	}
	
	if (i == 0) {
		grad_slist_append(slist, start, 1);
		if (pend)
			*pend = start + 1;
	} else {
		grad_slist_append_char(slist, val);
		if (pend)
			*pend = text + i;
	}
}


void
grad_slist_grow_backslash(grad_slist_t slist, char *text, char **endp)
{
	if (text[1] == '\\' || (unsigned char)text[1] > 127) {
		grad_slist_append_char(slist, text[1]);
		text += 2;
	} else if (isdigit(text[1])) 
		grad_slist_grow_backslash_num(slist, text, &text, 3, 8);
	else if (text[1] == 'x' || text[1] == 'X')
		grad_slist_grow_backslash_num(slist, text, &text, 2, 16);
	else {
		int c = grad_decode_backslash(text[1]);
		grad_slist_append_char(slist, c);
		text += 2;
	}
		
	*endp = text;
}

