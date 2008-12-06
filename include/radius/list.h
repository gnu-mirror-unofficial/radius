/* This file is part of GNU Radius
   Copyright (C) 2003,2004,2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#ifndef _gnu_radius_list_h
#define _gnu_radius_list_h

typedef struct grad_list grad_list_t;
typedef struct grad_iterator grad_iterator_t;

typedef int (*list_iterator_t)(void *item, void *data);
typedef int (*list_comp_t)(const void *, const void *);

grad_list_t *grad_list_create();
void grad_list_destroy(grad_list_t **list, list_iterator_t free, void *data);
void grad_list_iterate(grad_list_t *list, list_iterator_t itr, void *data);
void *grad_list_item(grad_list_t *list, size_t n);
size_t grad_list_count(grad_list_t *list);
void grad_list_append(grad_list_t *list, void *data);
void grad_list_prepend(grad_list_t *list, void *data);
int grad_list_insert_sorted(grad_list_t *list, void *data, list_comp_t cmp);
void *grad_list_locate(grad_list_t *list, void *data, list_comp_t cmp);
void *grad_list_remove(grad_list_t *list, void *data, list_comp_t cmp);

void *grad_iterator_current(grad_iterator_t *ip);
grad_iterator_t *grad_iterator_create(grad_list_t *list);
void grad_iterator_destroy(grad_iterator_t **ip);
void *grad_iterator_first(grad_iterator_t *ip);
void *grad_iterator_next(grad_iterator_t *ip);


#endif

