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
#include <radius.h>

/* Memory allocation interface */

VALUE_PAIR *
avp_alloc()
{
        return emalloc(sizeof(VALUE_PAIR));
}

void
avp_free(VALUE_PAIR *p)
{
        if (!p)
                return;
        if (p->type == TYPE_STRING || p->eval) 
                efree(p->avp_strvalue);
        efree(p);
}

/* A/V pair functions */

/* Create a copy of a pair */
VALUE_PAIR *
avp_dup(VALUE_PAIR *vp)
{
        VALUE_PAIR *ret = avp_alloc();

        memcpy(ret, vp, sizeof(VALUE_PAIR));
        ret->next = NULL;
        if (ret->type == TYPE_STRING || ret->eval) {
		ret->avp_strlength = vp->avp_strlength;
                ret->avp_strvalue = emalloc(ret->avp_strlength+1);
		memcpy(ret->avp_strvalue, vp->avp_strvalue,
		       ret->avp_strlength);
		ret->avp_strvalue[ret->avp_strlength] = 0;
	}
        return ret;
}

/* Create a pair with given attribute, length and value; */
VALUE_PAIR *
avp_create(int attr)
{
        VALUE_PAIR *pair;
        DICT_ATTR  *dict;

        dict = attr_number_to_dict(attr);
        if (!dict) {
                radlog(L_ERR, _("make_pair(): attribute %d not found in dictionary"),
                       attr);
                return NULL;
        }
        pair = avp_alloc();
        pair->name = dict->name;
        pair->attribute = attr;
        pair->type = dict->type;
        pair->prop = dict->prop;
	return pair;
}

VALUE_PAIR *
avp_create_integer(int attr, UINT4 value)
{
	VALUE_PAIR *pair = avp_create(attr);

	if (pair) 
		pair->avp_lvalue = value;
	return pair;
}

VALUE_PAIR *
avp_create_string(int attr, char *value)
{
	VALUE_PAIR *pair = avp_create(attr);
	if (pair) {
		pair->avp_strvalue = estrdup(value);
                pair->avp_strlength = strlen(value);
	}
	return pair;
}

VALUE_PAIR *
avp_create_binary(int attr, int length, u_char *value)
{
	VALUE_PAIR *pair = avp_create(attr);
	if (pair) {
                pair->avp_strlength = length;
                pair->avp_strvalue = emalloc(length + 1);
		memcpy(pair->avp_strvalue, value, length);
		pair->avp_strvalue[length] = 0;
	}
	return pair;
}

/* Add a pair to the end of a VALUE_PAIR list. */
VALUE_PAIR *
avp_move(VALUE_PAIR **first, VALUE_PAIR *new)
{
        VALUE_PAIR *pair, *prev = NULL;

        if (*first == NULL) {
                new->next = NULL;
                *first = new;
                return 0;
        }

        switch (ADDITIVITY(new->prop)) {
        case AP_ADD_NONE:
                for (pair = *first; pair; prev = pair, pair = pair->next)
                        if (pair->attribute == new->attribute)
                                return new;
                prev->next = new;
                new->next = NULL;
                return NULL;

        case AP_ADD_REPLACE:
                if ((*first)->attribute == new->attribute) {
                        prev = *first;
                        new->next = prev->next;
                        *first = new;
                        avp_free(prev);
                        return NULL;
                }
                for (pair = *first; pair; prev = pair, pair = pair->next)
                        if (pair->attribute == new->attribute) {
                                new->next = pair->next;
                                prev->next = new;
                                avp_free(pair);
                                return NULL;
                        }
                new->next = NULL;
                prev->next = new;
                return NULL;

        case AP_ADD_APPEND:
                for (pair = *first; pair->next; pair = pair->next)
                        ;
                new->next = NULL;
                pair->next = new;
                return NULL;
        }
        return new;
}

int
avp_cmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	int rc = 1;
	
	if (a->attribute != b->attribute || a->type != b->type)
		return 1;
	
	switch (a->type) {
	case TYPE_STRING:
		if (a->avp_strlength != b->avp_strlength)
			rc = 1;
		else
			rc = memcmp(a->avp_strvalue, b->avp_strvalue, 
                                    a->avp_strlength);
		break;

	case TYPE_INTEGER:
	case TYPE_IPADDR:
		rc = a->avp_lvalue != b->avp_lvalue;
		break;
	}
	return rc;
}

int
avp_null_string(VALUE_PAIR *pair)
{
	if (!pair)
		return 1;
	if (pair->type != TYPE_STRING)
		return 1;
	return strlen(pair->avp_strvalue) == 0;
}

/* A/V pairlist functions */

/* Release the memory used by a list of attribute-value pairs.
 */
void 
avl_free(VALUE_PAIR *pair)
{
        VALUE_PAIR *next;

        while (pair != NULL) {
                next = pair->next;
                avp_free(pair);
                pair = next;
        }
}


/* Find the pair with the matching attribute
 */
VALUE_PAIR * 
avl_find(VALUE_PAIR *first, int attr)
{
        while (first && first->attribute != attr)
                first = first->next;
        return first;
}

/* Find nth occurrence of a pair with the matching attribute. */
VALUE_PAIR * 
avl_find_n(VALUE_PAIR *first, int attr,	int n)
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
avl_delete(VALUE_PAIR **first, int attr)
{
        VALUE_PAIR *pair, *next, *last = NULL;

        for (pair = *first; pair; pair = next) {
                next = pair->next;
                if (pair->attribute == attr) {
                        if (last)
                                last->next = next;
                        else
                                *first = next;
                        avp_free(pair);
                } else
                        last = pair;
        }
}

/* Delete Nth pair with the matching attribute */
void 
avl_delete_n(VALUE_PAIR **first, int attr, int n)
{
	VALUE_PAIR *pair, *next, *last = NULL;

	for (pair = *first; pair; pair = next) {
		next = pair->next;
		if (pair->attribute == attr && n-- == 0) {
			if (last)
				last->next = next;
			else
				*first = next;
			avp_free(pair);
			break;
		} else
			last = pair;
	}
}


/* Move all attributes of a given type from one list to another */
void
avl_move_pairs(VALUE_PAIR **to, VALUE_PAIR **from, int (*fun)(),
	       void *closure)
{
        VALUE_PAIR *to_tail, *i, *next;
        VALUE_PAIR *iprev = NULL;

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
cmp_attr(int *valp, VALUE_PAIR *pair)
{
        return *valp == pair->attribute;
}

/* Move all attributes of a given type from one list to another */
void
avl_move_attr(VALUE_PAIR **to, VALUE_PAIR **from, int attr)
{
        avl_move_pairs(to, from, cmp_attr, &attr);
}

/* Move attributes from one list to the other honoring their additivity 
 */
void
avl_merge(VALUE_PAIR **dst_ptr, VALUE_PAIR **src_ptr)
{
        VALUE_PAIR *src, *next, *src_head, *src_tail;

        if (*dst_ptr == NULL) {
                *dst_ptr = *src_ptr;
                *src_ptr = NULL;
                return;
        }

        src_head = src_tail = NULL;
        src = *src_ptr;
        while (src) {
                next = src->next;
                src = avp_move(dst_ptr, src);
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
avl_add_list(VALUE_PAIR **first, VALUE_PAIR *new)
{
        VALUE_PAIR *pair;
        
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
avl_add_pair(VALUE_PAIR **first, VALUE_PAIR *new)
{
        if (!new)
                return;
        new->next = NULL;
        avl_add_list(first, new);
}


/* Create a copy of a pair list. */
VALUE_PAIR *
avl_dup(VALUE_PAIR *from)
{
        VALUE_PAIR *first = NULL;
        VALUE_PAIR *last = NULL;
        VALUE_PAIR *temp;

        for ( ; from; from = from->next) {
                temp = avp_alloc();
                memcpy(temp, from, sizeof(VALUE_PAIR));
                if (temp->type == TYPE_STRING || temp->eval) {
			char *p = emalloc(temp->avp_strlength+1);
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
avl_fprint(FILE *fp, VALUE_PAIR *avl)
{
        char *save;
        for (;avl; avl = avl->next) {
                fprintf(fp, "    %s\n", format_pair(avl, &save));
                free(save);
        }
}

int
avl_cmp(VALUE_PAIR *a, VALUE_PAIR *b, int prop)
{
	int cmp_count = 0;
	
	for (; a; a = a->next) {
		if (a->prop & prop) {
			VALUE_PAIR *p = avl_find(b, a->attribute);
			if (!p || avp_cmp(a, p))
				return 1;
			cmp_count++;
		}
	}
	return cmp_count == 0;
}
