/* This file is part of GNU Radius
   Copyright (C) 2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#ifndef LIST_H
#define LIST_H

typedef struct list RAD_LIST;
typedef struct iterator ITERATOR;

typedef int (*list_iterator_t)(void *item, void *data);
typedef int (*list_comp_t)(const void *, const void *);

RAD_LIST *grad_list_create();
void grad_list_destroy(RAD_LIST **list, list_iterator_t free, void *data);
void grad_list_iterate(RAD_LIST *list, list_iterator_t itr, void *data);
void *grad_list_item(RAD_LIST *list, size_t n);
size_t grad_list_count(RAD_LIST *list);
void grad_list_append(RAD_LIST *list, void *data);
void grad_list_prepend(RAD_LIST *list, void *data);
int grad_list_insert_sorted(struct list *list, void *data, list_comp_t cmp);
void *grad_list_locate(RAD_LIST *list, void *data, list_comp_t cmp);
void *grad_list_remove(RAD_LIST *list, void *data, list_comp_t cmp);

void *iterator_current(ITERATOR *ip);
ITERATOR *iterator_create(RAD_LIST *list);
void iterator_destroy(ITERATOR **ip);
void *iterator_first(ITERATOR *ip);
void *iterator_next(ITERATOR *ip);


#endif

