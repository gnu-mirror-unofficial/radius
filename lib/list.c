/* This file is part of GNU Radius.
   Copyright (C) 2003,2004 Free Software Foundation
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <stdlib.h>
#include <radius/radius.h>
#include <radius/list.h>

struct list_entry {
	struct list_entry *next;
	void *data;
};

struct list {
	size_t count;
	struct list_entry *head, *tail;
	struct iterator *itr;
};

struct iterator {
	struct iterator *next;
	grad_list_t *list;
	struct list_entry *cur;
	int advanced;
};

struct list *
grad_list_create()
{
	struct list *p = grad_emalloc(sizeof(*p));
	p->head = p->tail = NULL;
	p->itr = NULL;
	return p;
}

void
grad_list_destroy(struct list **plist, list_iterator_t user_free, void *data)
{
	struct list_entry *p;

	if (!*plist)
		return;
	
	p = (*plist)->head;
	while (p) {
		struct list_entry *next = p->next;
		if (user_free)
			user_free(p->data, data);
		grad_free(p);
		p = next;
	}
	grad_free(*plist);
	*plist = NULL;
}

void *
grad_iterator_current(grad_iterator_t *ip)
{
	if (!ip)
		return NULL;
	return ip->cur ? ip->cur->data : NULL;
}

grad_iterator_t *
grad_iterator_create(grad_list_t *list)
{
	grad_iterator_t *itr;

	if (!list)
		return NULL;
	itr = grad_emalloc(sizeof(*itr));
	itr->list = list;
	itr->cur = NULL;
	itr->next = list->itr;
	itr->advanced = 0;
	list->itr = itr;
	return itr;
}

void
grad_iterator_destroy(grad_iterator_t **ip)
{
	grad_iterator_t *itr, *prev;

	if (!ip || !*ip)
		return;
	for (itr = (*ip)->list->itr, prev = NULL;
	     itr;
	     prev = itr, itr = itr->next)
		if (*ip == itr)
			break;
	if (itr) {
		if (prev)
			prev->next = itr->next;
		else
			itr->list->itr = itr->next;
		grad_free(itr);
		*ip = NULL;
	}
		
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
_iterator_advance(grad_iterator_t *ip, struct list_entry *e)
{
	for (; ip; ip = ip->next) {
		if (ip->cur == e) {
			ip->cur = e->next;
			ip->advanced++;
		}
	}
}

void *
grad_list_item(struct list *list, size_t n)
{
	struct list_entry *p;
	if (n >= list->count)
		return NULL;
	for (p = list->head; n > 0 && p; p = p->next, n--)
		;
	return p->data;
}

size_t
grad_list_count(struct list *list)
{
	if (!list)
		return 0;
	return list->count;
}

void
grad_list_append(struct list *list, void *data)
{
	struct list_entry *ep;

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
grad_list_prepend(struct list *list, void *data)
{
	struct list_entry *ep;

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
grad_list_remove(struct list *list, void *data, list_comp_t cmp)
{
	struct list_entry *p, *prev;

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

void
grad_list_iterate(struct list *list, list_iterator_t func, void *data)
{
	grad_iterator_t *itr;
	void *p;
	
	if (!list)
		return;
	itr = grad_iterator_create(list);
	if (!itr)
		return;
	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) {
		if (func(p, data))
			break;
	}
	grad_iterator_destroy(&itr);
}

void *
grad_list_locate(struct list *list, void *data, list_comp_t cmp)
{
	struct list_entry *cur;
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
grad_list_insert_sorted(struct list *list, void *data, list_comp_t cmp)
{
	struct list_entry *cur, *prev;
	
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
		struct list_entry *ep = grad_emalloc(sizeof(*ep));
		ep->data = data;
		ep->next = cur;
		prev->next = ep;
	}
	return 0;
}

