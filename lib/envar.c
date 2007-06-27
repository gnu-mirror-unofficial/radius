/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007 Free Software Foundation, Inc.

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
#include <stdlib.h>
#include <string.h>
#include <radlib.h>

typedef struct envar {
        char *name;
        char *value;
} ENVAR;

static void
grad_envar_assign_internal(char *name, int namelen, char *value, int valuelen,
			   grad_list_t **plist)
{
	ENVAR *env;
	char *p;
                
	if (!value) {
		if (namelen > 2 && memcmp(name, "no", 2) == 0) {
			name += 2;
			namelen -= 2;
			value = "0";
			valuelen = 1;
		} else {
			value = "1";
			valuelen = 1;
		}
	} 
			
	env = grad_emalloc(sizeof(*env));
	env->name = grad_emalloc(namelen + 1);
	memcpy(env->name, name, namelen);
	env->name[namelen] = 0;

	env->value = grad_emalloc(valuelen + 1);
	memcpy(env->value, value, valuelen);
	env->value[valuelen] = 0;

	if (!*plist)
		*plist = grad_list_create();
	grad_list_append(*plist, env);
}

void
grad_envar_assign(char *name, char *value, grad_list_t **plist)
{
	grad_envar_assign_internal(name, strlen(name),
				   value,
				   value ? strlen(value) : 0,
				   plist);
}


static void
grad_envar_parse_grad_argcv_internal(int argc, char **argv, grad_list_t **plist)
{
	int i;
	char *p;
	
	for (i = 0; i < argc; i++) {
                if (argv[i][0] == ',')
                        continue;
                p = strchr(argv[i], '=');
                if (p) 
			grad_envar_assign_internal(argv[i], p - argv[i],
						   p + 1, strlen(p + 1),
						   plist);
		else
			grad_envar_assign_internal(argv[i], strlen(argv[i]),
						   NULL, 0,
						   plist);
        }
}

static void
grad_envar_parse_internal(char *str, grad_list_t **plist)
{
        int argc;
        char **argv;

        if (grad_argcv_get(str, ",", NULL, &argc, &argv)) {
                if (argv)
                        grad_argcv_free(argc, argv);
                return;
        }
	grad_envar_parse_grad_argcv_internal(argc, argv, plist);
	grad_argcv_free(argc, argv);
}

grad_envar_t *
grad_envar_parse(char *str)
{
	grad_list_t *list = NULL;
        grad_envar_parse_internal(str, &list);
        return list;
}

grad_envar_t *
grad_envar_parse_argcv(int argc, char **argv)
{
	grad_list_t *list = NULL;
        while (argc--) {
		grad_envar_parse_internal(*argv++, &list);
        }
        return list;
}

static int
grad_envar_free(void *item, void *data)
{
        ENVAR *env = item;
        grad_free(env->name);
        grad_free(env->value);
	grad_free(env);
	return 0;
}

void
grad_envar_free_list(grad_envar_t **evp)
{
	grad_list_destroy(evp, grad_envar_free, NULL);
}

char *
grad_envar_lookup(grad_envar_t *env, char *name)
{
	ENVAR *p;
	grad_iterator_t *itr = grad_iterator_create(env);

	if (!itr)
		return NULL;
	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) {
                if (strcmp(p->name, name) == 0)
                        break;
        }
        grad_iterator_destroy(&itr);
        return p ? p->value : NULL;
}

char *
grad_envar_lookup_str(grad_envar_t *env, char *name, char *defval)
{
        char *s;

        if (s = grad_envar_lookup(env, name))
                return s;
        return defval;
}

int
grad_envar_lookup_int(grad_envar_t *env, char *name, int defval)
{
        char *s;
        
        if (s = grad_envar_lookup(env, name))
                return atoi(s);
        return defval;
}

ENVAR *
grad_envar_dup(ENVAR *env)
{
        ENVAR *ep;

        ep = grad_emalloc(sizeof(*ep));
        ep->name  = grad_estrdup(env->name);
        ep->value = grad_estrdup(env->value);
        return ep;
}

grad_envar_t *
grad_envar_merge_lists(grad_envar_t *prim, grad_envar_t *sec)
{
        grad_envar_t *list;
	ENVAR *p;
	grad_iterator_t *itr;
        
        list = grad_list_create();
	itr = grad_iterator_create(sec);
	if (itr) {
		for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr))
                	if (!grad_envar_lookup(prim, p->name)) {
				grad_list_append(list, grad_envar_dup(p));
                	}
                grad_iterator_destroy(&itr);
        }
        itr = grad_iterator_create(prim);
        if (itr) {
        	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) 
                	grad_list_append(list, grad_envar_dup(p));
                grad_iterator_destroy(&itr);
        }
        return list;
}

