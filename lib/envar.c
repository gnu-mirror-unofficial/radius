/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

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
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <mem.h>
#include <envar.h>
#include <argcv.h>
#include <list.h>

typedef struct envar {
        char *name;
        char *value;
} ENVAR;

static void
grad_envar_parse_internal(char *str, RAD_LIST **plist)
{
        int i;
        int argc;
        char **argv;

        if (argcv_get(str, ",", NULL, &argc, &argv)) {
                if (argv)
                        argcv_free(argc, argv);
                return;
        }

        for (i = 0; i < argc; i++) {
                ENVAR *env;
                char *p;
                
                if (argv[i][0] == ',')
                        continue;
                env = emalloc(sizeof(*env));
                p = strchr(argv[i], '=');
                if (p) {
                        int len = p - argv[i];
                        env->name = emalloc(len + 1);
                        memcpy(env->name, argv[i], len);
                        env->name[len] = 0;
                        env->value = estrdup(p+1);
                } else if (strlen(argv[i]) > 2
                           && memcmp(argv[i], "no", 2) == 0) {
                        env->name = estrdup(argv[i]+2);
                        env->value = estrdup("0");
                } else {
                        env->name = estrdup(argv[i]);
                        env->value = estrdup("1");
                }
		if (!*plist)
			*plist = grad_list_create();
		grad_list_append(*plist, env);
        }
	argcv_free(argc, argv);
}

grad_envar_t *
grad_envar_parse(char *str)
{
	RAD_LIST *list = NULL;
        grad_envar_parse_internal(str, &list);
        return list;
}

grad_envar_t *
grad_envar_parse_argcv(int argc, char **argv)
{
	RAD_LIST *list = NULL;
        while (argc--) {
                grad_envar_parse_internal(*argv++, &list);
        }
        return list;
}

static int
grad_envar_free(void *item, void *data)
{
        ENVAR *env = item;
        efree(env->name);
        efree(env->value);
	efree(env);
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
	ITERATOR *itr = iterator_create(env);

	if (!itr)
		return NULL;
	for (p = iterator_first(itr); p; p = iterator_next(itr)) {
                if (strcmp(p->name, name) == 0)
                        break;
        }
        iterator_destroy(&itr);
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

        ep = emalloc(sizeof(*ep));
        ep->name  = estrdup(env->name);
        ep->value = estrdup(env->value);
        return ep;
}

grad_envar_t *
grad_envar_merge_lists(grad_envar_t *prim, grad_envar_t *sec)
{
        grad_envar_t *list;
	ENVAR *p;
	ITERATOR *itr;
        
        list = grad_list_create();
	itr = iterator_create(sec);
	if (itr) {
		for (p = iterator_first(itr); p; p = iterator_next(itr))
                	if (!grad_envar_lookup(prim, p->name)) {
				grad_list_append(list, grad_envar_dup(p));
                	}
                iterator_destroy(&itr);
        }
        itr = iterator_create(prim);
        if (itr) {
        	for (p = iterator_first(itr); p; p = iterator_next(itr)) 
                	grad_list_append(list, grad_envar_dup(p));
                iterator_destroy(&itr);
        }
        return list;
}

