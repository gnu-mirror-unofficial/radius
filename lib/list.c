/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2007,2008 Free Software Foundation
  
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
#include <radius/radius.h>
#include <radius/list.h>

struct grad_list_entry {
	struct grad_list_entry *next;
	void *data;
};

struct grad_list {
	size_t count;
	struct grad_list_entry *head, *tail;
	struct grad_iterator *itr;
};

struct grad_iterator {
	struct grad_iterator *next;
	grad_list_t *list;
	struct grad_list_entry *cur;
	int advanced;
};

struct grad_list *
grad_list_create()
{
	struct grad_list *p = grad_emalloc(sizeof(*p));
	p->head = p->tail = NULL;
	p->itr = NULL;
	return p;
}

void
grad_list_destroy(struct grad_list **plist, list_iterator_t user_free, void *data)
{
	struct grad_list_entry *p;
	struct grad_list *list;
	
	if (!*plist)
		return;

	list = *plist;
	*plist = NULL;
	p = list->head;
	while (p) {
		struct grad_list_entry *next = p->next;
		if (user_free)
			user_free(p->data, data);
		grad_free(p);
		p = next;
	}
	grad_free(list);
}

void *
grad_iterator_current(grad_iterator_t *ip)
{
	if (!ip)
		return NULL;
	return ip->cur ? ip->cur->data : NULL;
}

static void
grad_iterator_attach(grad_iterator_t *itr, grad_list_t *list)
{
	itr->list = list;
	itr->cur = NULL;
	itr->next = list->itr;
	itr->advanced = 0;
	list->itr = itr;	
}

static grad_iterator_t *
grad_iterator_detach(grad_iterator_t *iter)
{
	grad_iterator_t *cur, *prev;

	for (cur = iter->list->itr, prev = NULL;
	     cur;
	     prev = cur, cur = cur->next)
		if (cur == iter)
			break;
	
	if (cur) {
		if (prev)
			prev->next = cur->next;
		else
			cur->list->itr = cur->next;
	}
	return cur;
}
		     
grad_iterator_t *
grad_iterator_create(grad_list_t *list)
{
	grad_iterator_t *itr;

	if (!list)
		return NULL;
	itr = grad_emalloc(sizeof(*itr));
	grad_iterator_attach(itr, list);
	return itr;
}

void
grad_iterator_destroy(grad_iterator_t **ip)
{
	grad_iterator_t *itr;
	
	if (!ip || !*ip)
		return;
	itr = grad_iterator_detach(*ip);
	if (itr)
		grad_free(itr);
	*ip = NULL;
}
		
void *
grad_iterator_first(grad_iterator_t *ip)
{
	if (!ip)
		return NULL;
	ip->cur = ip->list->head;
	ip->advanced = 0;
	return grad_iterator_current(ip);
}

void *
grad_iterator_next(grad_iterator_t *ip)
{
	if (!ip || !ip->cur)
		return NULL;
	if (!ip->advanced)
		ip->cur = ip->cur->next;
	ip->advanced = 0;
	return grad_iterator_current(ip);
}	

static void
_iterator_advance(grad_iterator_t *ip, struct grad_list_entry *e)
{
	for (; ip; ip = ip->next) {
		if (ip->cur == e) {
			ip->cur = e->next;
			ip->advanced++;
		}
	}
}

void *
grad_list_item(struct grad_list *list, size_t n)
{
	struct grad_list_entry *p;
	if (!list || n >= list->count)
		return NULL;
	for (p = list->head; n > 0 && p; p = p->next, n--)
		;
	return p->data;
}

size_t
grad_list_count(struct grad_list *list)
{
	if (!list)
		return 0;
	return list->count;
}

void
grad_list_append(struct grad_list *list, void *data)
{
	struct grad_list_entry *ep;

	if (!list)
		return;
	ep = grad_emalloc(sizeof(*ep));
	ep->next = NULL;
	ep->data = data;
	if (list->tail)
		list->tail->next = ep;
	else
		list->head = ep;
	list->tail = ep;
	list->count++;
}

void
grad_list_prepend(struct grad_list *list, void *data)
{
	struct grad_list_entry *ep;

	if (!list)
		return;
	ep = grad_emalloc(sizeof(*ep));
	ep->data = data;
	ep->next = list->head;
	list->head = ep;
	if (!list->tail)
		list->tail = list->head;
	list->count++;
}

static int
cmp_ptr(const void *a, const void *b)
{
	return a != b;
}

void *
grad_list_remove(struct grad_list *list, void *data, list_comp_t cmp)
{
	struct grad_list_entry *p, *prev;

	if (!list)
		return NULL;
	if (!list->head)
		return NULL;
	if (!cmp)
		cmp = cmp_ptr;
	for (p = list->head, prev = NULL; p; prev = p, p = p->next)
		if (cmp(p->data, data) == 0)
			break;

	if (!p)
		return 0;
	_iterator_advance(list->itr, p);
	if (p == list->head) {
		list->head = list->head->next;
		if (!list->head)
			list->tail = NULL;
	} else 
		prev->next = p->next;
	
	if (p == list->tail)
		list->tail = prev;
	
	grad_free(p);
	list->count--;
	
	return data;
}

/* Note: if modifying this function, make sure it does not allocate any
   memory! */
void
grad_list_iterate(struct grad_list *list, list_iterator_t func, void *data)
{
	grad_iterator_t itr;
	void *p;
	
	if (!list)
		return;
	grad_iterator_attach(&itr, list);
	for (p = grad_iterator_first(&itr); p; p = grad_iterator_next(&itr)) {
		if (func(p, data))
			break;
	}
	grad_iterator_detach(&itr);
}

void *
grad_list_locate(struct grad_list *list, void *data, list_comp_t cmp)
{
	struct grad_list_entry *cur;
	if (!list)
		return NULL;
	if (!cmp)
		cmp = cmp_ptr;
	for (cur = list->head; cur; cur = cur->next)
		if (cmp(cur->data, data) == 0)
			break;
	return cur ? cur->data : NULL;
}
	
int
grad_list_insert_sorted(struct grad_list *list, void *data, list_comp_t cmp)
{
	struct grad_list_entry *cur, *prev;
	
	if (!list)
		return -1;
	if (!cmp)
		return -1;
		
	for (cur = list->head, prev = NULL; cur; prev = cur, cur = cur->next)
		if (cmp(cur->data, data) > 0)
			break;

	if (!prev) {
		grad_list_prepend(list, data);
	} else if (!cur) {
		grad_list_append(list, data);
	} else {
		struct grad_list_entry *ep = grad_emalloc(sizeof(*ep));
		ep->data = data;
		ep->next = cur;
		list->count++;
		prev->next = ep;
	}
	return 0;
}

