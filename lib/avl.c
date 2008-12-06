/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007,
   2008 Free Software Foundation, Inc.

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
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#include <radlib.h>

/* Memory allocation interface */

grad_avp_t *
grad_avp_alloc()
{
        return grad_emalloc(sizeof(grad_avp_t));
}

void
grad_avp_free(grad_avp_t *p)
{
        if (!p)
                return;
        if (p->type == GRAD_TYPE_STRING || p->eval_type != grad_eval_const) 
                grad_free(p->avp_strvalue);
        grad_free(p);
}

/* A/V pair functions */

/* Create a copy of a pair */
grad_avp_t *
grad_avp_dup(grad_avp_t *vp)
{
        grad_avp_t *ret = grad_avp_alloc();

        memcpy(ret, vp, sizeof(grad_avp_t));
        ret->next = NULL;
        if (ret->type == GRAD_TYPE_STRING || ret->eval_type != grad_eval_const) {
		ret->avp_strlength = vp->avp_strlength;
                ret->avp_strvalue = grad_emalloc(ret->avp_strlength+1);
		memcpy(ret->avp_strvalue, vp->avp_strvalue,
		       ret->avp_strlength);
		ret->avp_strvalue[ret->avp_strlength] = 0;
	}
        return ret;
}

/* Create a pair with given attribute */
grad_avp_t *
grad_avp_create(int attr)
{
        grad_avp_t *pair;
        grad_dict_attr_t  *dict;

        dict = grad_attr_number_to_dict(attr);
        if (!dict) {
                grad_log(GRAD_LOG_ERR,
                         _("make_pair(): attribute %d not found in dictionary"),
                         attr);
                return NULL;
        }
        pair = grad_avp_alloc();
        pair->name = dict->name;
        pair->attribute = attr;
        pair->type = dict->type;
        pair->prop = dict->prop;
	return pair;
}

grad_avp_t *
grad_avp_create_integer(int attr, grad_uint32_t value)
{
	grad_avp_t *pair = grad_avp_create(attr);

	if (pair) 
		pair->avp_lvalue = value;
	return pair;
}

grad_avp_t *
grad_avp_create_string(int attr, char *value)
{
	grad_avp_t *pair = grad_avp_create(attr);
	if (pair) {
		pair->avp_strvalue = grad_estrdup(value);
                pair->avp_strlength = strlen(value);
	}
	return pair;
}

grad_avp_t *
grad_avp_create_binary(int attr, int length, u_char *value)
{
	grad_avp_t *pair = grad_avp_create(attr);
	if (pair) {
                pair->avp_strlength = length;
                pair->avp_strvalue = grad_emalloc(length + 1);
		memcpy(pair->avp_strvalue, value, length);
		pair->avp_strvalue[length] = 0;
	}
	return pair;
}

/* Add a pair to the end of a grad_avp_t list. */
grad_avp_t *
grad_avp_move(grad_avp_t **first, grad_avp_t *new)
{
        grad_avp_t *pair, *prev = NULL;

        if (*first == NULL) {
                new->next = NULL;
                *first = new;
                return 0;
        }

        switch (GRAD_GET_ADDITIVITY(new->prop)) {
        case GRAD_AP_ADD_NONE:
                for (pair = *first; pair; prev = pair, pair = pair->next)
                        if (pair->attribute == new->attribute)
                                return new;
                prev->next = new;
                new->next = NULL;
                return NULL;

        case GRAD_AP_ADD_REPLACE:
                if ((*first)->attribute == new->attribute) {
                        prev = *first;
                        new->next = prev->next;
                        *first = new;
                        grad_avp_free(prev);
                        return NULL;
                }
                for (pair = *first; pair; prev = pair, pair = pair->next)
                        if (pair->attribute == new->attribute) {
                                new->next = pair->next;
                                prev->next = new;
                                grad_avp_free(pair);
                                return NULL;
                        }
                new->next = NULL;
                prev->next = new;
                return NULL;

        case GRAD_AP_ADD_APPEND:
                for (pair = *first; pair->next; pair = pair->next)
                        ;
                new->next = NULL;
                pair->next = new;
                return NULL;
        }
        return new;
}

int
grad_avp_cmp(grad_avp_t *a, grad_avp_t *b)
{
	int rc = 1;
	
	if (a->attribute != b->attribute || a->type != b->type)
		return 1;
	
	switch (a->type) {
	case GRAD_TYPE_STRING:
		if (a->avp_strlength != b->avp_strlength)
			rc = 1;
		else
			rc = memcmp(a->avp_strvalue, b->avp_strvalue, 
                                    a->avp_strlength);
		break;

	case GRAD_TYPE_INTEGER:
	case GRAD_TYPE_IPADDR:
		rc = a->avp_lvalue != b->avp_lvalue;
		break;
	}
	return rc;
}

int
grad_avp_null_string_p(grad_avp_t *pair)
{
	if (!pair)
		return 1;
	if (pair->type != GRAD_TYPE_STRING)
		return 1;
	return strlen(pair->avp_strvalue) == 0;
}

/* A/V pairlist functions */

/* Release the memory used by a list of attribute-value pairs.
 */
void 
grad_avl_free(grad_avp_t *pair)
{
        grad_avp_t *next;

        while (pair != NULL) {
                next = pair->next;
                grad_avp_free(pair);
                pair = next;
        }
}


/* Find the pair with the matching attribute
 */
grad_avp_t * 
grad_avl_find(grad_avp_t *first, int attr)
{
        while (first && first->attribute != attr)
                first = first->next;
        return first;
}

/* Find nth occurrence of a pair with the matching attribute. */
grad_avp_t * 
grad_avl_find_n(grad_avp_t *first, int attr,	int n)
{
	for ( ; first; first = first->next) {
		if (first->attribute == attr && n-- == 0)
			break;
	}
	return first;
}

/* Delete the pairs with the matching attribute
 */
void 
grad_avl_delete(grad_avp_t **first, int attr)
{
        grad_avp_t *pair, *next, *last = NULL;

        for (pair = *first; pair; pair = next) {
                next = pair->next;
                if (pair->attribute == attr) {
                        if (last)
                                last->next = next;
                        else
                                *first = next;
                        grad_avp_free(pair);
                } else
                        last = pair;
        }
}

/* Delete Nth pair with the matching attribute */
void 
grad_avl_delete_n(grad_avp_t **first, int attr, int n)
{
	grad_avp_t *pair, *next, *last = NULL;

	for (pair = *first; pair; pair = next) {
		next = pair->next;
		if (pair->attribute == attr && n-- == 0) {
			if (last)
				last->next = next;
			else
				*first = next;
			grad_avp_free(pair);
			break;
		} else
			last = pair;
	}
}


/* Move all attributes of a given type from one list to another */
void
grad_avl_move_pairs(grad_avp_t **to,
		    grad_avp_t **from,
		    int (*fun)(void *, grad_avp_t *),
		    void *closure)
{
        grad_avp_t *to_tail, *i, *next;
        grad_avp_t *iprev = NULL;

        /*
         *      Find the last pair in the "to" list and put it in "to_tail".
         */
        if (*to != NULL) {
                to_tail = *to;
                for(i = *to; i; i = i->next)
                        to_tail = i;
        } else
                to_tail = NULL;

        for(i = *from; i; i = next) {
                next = i->next;

                if ((*fun)(closure, i) == 0) {
                        iprev = i;
                        continue;
                }

                /*
                 *      Remove the attribute from the "from" list.
                 */
                if (iprev)
                        iprev->next = next;
                else
                        *from = next;

                /*
                 *      Add the attribute to the "to" list.
                 */
                if (to_tail)
                        to_tail->next = i;
                else
                        *to = i;
                to_tail = i;
                i->next = NULL;
        }
}

static int
cmp_attr(void *data, grad_avp_t *pair)
{
	int *valp = data; 
        return *valp == pair->attribute;
}

/* Move all attributes of a given type from one list to another */
void
grad_avl_move_attr(grad_avp_t **to, grad_avp_t **from, int attr)
{
        grad_avl_move_pairs(to, from, cmp_attr, &attr);
}

/* Move attributes from one list to the other honoring their additivity 
 */
void
grad_avl_merge(grad_avp_t **dst_ptr, grad_avp_t **src_ptr)
{
        grad_avp_t *src, *next, *src_head, *src_tail;

        if (*dst_ptr == NULL) {
                *dst_ptr = *src_ptr;
                *src_ptr = NULL;
                return;
        }

        src_head = src_tail = NULL;
        src = *src_ptr;
        while (src) {
                next = src->next;
                src = grad_avp_move(dst_ptr, src);
                if (src) {
                        if (src_tail)
                                src_tail->next = src;
                        else
                                src_head = src;
                        src_tail = src;
                }
                src = next;
        }
        *src_ptr = src_head;
}

/* Append the list `new' to the end of the list `*first' */
void
grad_avl_add_list(grad_avp_t **first, grad_avp_t *new)
{
        grad_avp_t *pair;
        
        if (*first == NULL) {
                *first = new;
                return;
        }
        for (pair = *first; pair->next; pair = pair->next)
                ;
        pair->next = new;
}

/* Add a single pair to the list */
void
grad_avl_add_pair(grad_avp_t **first, grad_avp_t *new)
{
        if (!new)
                return;
        new->next = NULL;
        grad_avl_add_list(first, new);
}


/* Create a copy of a pair list. */
grad_avp_t *
grad_avl_dup(grad_avp_t *from)
{
        grad_avp_t *first = NULL;
        grad_avp_t *last = NULL;
        grad_avp_t *temp;

        for ( ; from; from = from->next) {
                temp = grad_avp_alloc();
                memcpy(temp, from, sizeof(grad_avp_t));
                if (temp->type == GRAD_TYPE_STRING || temp->eval_type != grad_eval_const) {
			char *p = grad_emalloc(temp->avp_strlength+1);
			memcpy(p, temp->avp_strvalue, temp->avp_strlength);
			p[temp->avp_strlength] = 0;
			temp->avp_strvalue = p;
		}
                temp->next = NULL;
                if (last)
                        last->next = temp;
                else
                        first = temp;
                last = temp;
        }

        return first;
}

/* write a pairlist to the file */
void
grad_avl_fprint(FILE *fp, char *prefix, int typeflag, grad_avp_t *avl)
{
        char *save;
	if (!prefix)
		prefix = "";
        for (;avl; avl = avl->next) {
                fprintf(fp, "%s%s\n", prefix,
			grad_format_pair(avl, typeflag, &save));
                free(save);
        }
}

int
grad_avl_cmp(grad_avp_t *a, grad_avp_t *b, int prop)
{
	int cmp_count = 0;
	
	for (; a; a = a->next) {
		if (a->prop & prop) {
			grad_avp_t *p = grad_avl_find(b, a->attribute);
			if (!p || grad_avp_cmp(a, p))
				return 1;
			cmp_count++;
		}
	}
	return cmp_count == 0;
}
