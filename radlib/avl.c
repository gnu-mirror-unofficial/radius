/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

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
        return Alloc_entry(VALUE_PAIR);
}

void
avp_free(p)     
        VALUE_PAIR *p;
{
        if (p->type == TYPE_STRING || p->eval) {
                free_string(p->strvalue);
        }
        free_entry(p);
}

/* A/V pair functions */

/* Create a copy of a pair */
VALUE_PAIR *
avp_dup(vp)
        VALUE_PAIR *vp;
{
        VALUE_PAIR *ret = avp_alloc();

        memcpy(ret, vp, sizeof(VALUE_PAIR));
        ret->next = NULL;
        if (ret->type == TYPE_STRING)
                ret->strvalue = dup_string(vp->strvalue);
        return ret;
}

/* Create a pair with given attribute, length and value; */
VALUE_PAIR *
avp_create(attr, length, strval, lval)
        int attr;
        int length;
        char *strval;
        int lval;
{
        VALUE_PAIR *pair;
        DICT_ATTR  *dict;

        dict = attr_number_to_dict(attr);
        if (!dict) {
                radlog(L_ERR, _("make_pair(): dictionary attr %d not found"),
                       attr);
                return NULL;
        }
        pair = avp_alloc();
        pair->name = dict->name;
        pair->attribute = attr;
        pair->type = dict->type;
        pair->prop = dict->prop;
        if (strval) {
                pair->strlength = length;
                pair->strvalue = make_string(strval);
        } else
                pair->lvalue = lval;

        return pair;
}

/* Add a pair to the end of a VALUE_PAIR list. */
VALUE_PAIR *
avp_move(first, new)
        VALUE_PAIR **first; 
        VALUE_PAIR *new;
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

/* A/V pairlist functions */

/* Release the memory used by a list of attribute-value pairs.
 */
void 
avl_free(pair)
        VALUE_PAIR *pair;
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
avl_find(first, attr)
        VALUE_PAIR *first; 
        int attr;
{
        while (first && first->attribute != attr)
                first = first->next;
        return first;
}

/* Delete the pairs with the matching attribute
 */
void 
avl_delete(first, attr)
        VALUE_PAIR **first; 
        int attr;
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

/* Move all attributes of a given type from one list to another */
void
avl_move_pairs(to, from, fun, closure)
        VALUE_PAIR **to;
        VALUE_PAIR **from;
        int (*fun)();
        void *closure;
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

int
cmp_attr(valp, pair)
        int *valp;
        VALUE_PAIR *pair;
{
        return *valp == pair->attribute;
}

/* Move all attributes of a given type from one list to another */
void
avl_move_attr(to, from, attr)
        VALUE_PAIR **to;
        VALUE_PAIR **from;
        int attr;
{
        avl_move_pairs(to, from, cmp_attr, &attr);
}

/* Move attributes from one list to the other honoring their additivity 
 */
void
avl_merge(dst_ptr, src_ptr)
        VALUE_PAIR **dst_ptr;
        VALUE_PAIR **src_ptr;
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
avl_add_list(first, new)
        VALUE_PAIR **first;
        VALUE_PAIR *new;
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
avl_add_pair(first, new)
        VALUE_PAIR **first;
        VALUE_PAIR *new;
{
        if (!new)
                return;
        new->next = NULL;
        avl_add_list(first, new);
}


/* Create a copy of a pair list. */
VALUE_PAIR *
avl_dup(from)
        VALUE_PAIR *from;
{
        VALUE_PAIR *first = NULL;
        VALUE_PAIR *last = NULL;
        VALUE_PAIR *temp;

        for ( ; from; from = from->next) {
                temp = avp_alloc();
                memcpy(temp, from, sizeof(VALUE_PAIR));
                if (temp->type == TYPE_STRING)
                        temp->strvalue = dup_string(temp->strvalue);
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
avl_fprint(fp, avl)
        FILE *fp;
        VALUE_PAIR *avl;
{
        char *save;
        for (;avl; avl = avl->next) {
                fprintf(fp, "    %s\n", format_pair(avl, &save));
                free(save);
        }
}

