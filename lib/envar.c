/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2003 Sergey Poznyakoff
  
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
envar_parse_internal(char *str, RAD_LIST **plist)
{
        int i;
        int argc;
        char **argv;

        if (argcv_get(str, ",", &argc, &argv)) {
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
			*plist = list_create();
		list_append(*plist, env);
        }
}

envar_t *
envar_parse(char *str)
{
	RAD_LIST *list = NULL;
        envar_parse_internal(str, &list);
        return list;
}

envar_t *
envar_parse_argcv(int argc, char **argv)
{
	RAD_LIST *list = NULL;
        while (argc--) {
                envar_parse_internal(*argv++, &list);
        }
        return list;
}

static int
envar_free(void *item, void *data)
{
        ENVAR *env = item;
        efree(env->name);
        efree(env->value);
	efree(env);
	return 0;
}

void
envar_free_list(envar_t **evp)
{
	list_destroy(evp, envar_free, NULL);
}

char *
envar_lookup(envar_t *env, char *name)
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
envar_lookup_str(envar_t *env, char *name, char *defval)
{
        char *s;

        if (s = envar_lookup(env, name))
                return s;
        return defval;
}

int
envar_lookup_int(envar_t *env, char *name, int defval)
{
        char *s;
        
        if (s = envar_lookup(env, name))
                return atoi(s);
        return defval;
}

ENVAR *
envar_dup(ENVAR *env)
{
        ENVAR *ep;

        ep = emalloc(sizeof(*ep));
        ep->name  = estrdup(env->name);
        ep->value = estrdup(env->value);
        return ep;
}

envar_t *
envar_merge_lists(envar_t *prim, envar_t *sec)
{
        envar_t *list;
	ENVAR *p;
	ITERATOR *itr;
        
        list = list_create();
	itr = iterator_create(sec);
	if (itr) {
		for (p = iterator_first(itr); p; p = iterator_next(itr))
                	if (!envar_lookup(prim, p->name)) {
				list_append(list, envar_dup(p));
                	}
                iterator_destroy(&itr);
        }
        itr = iterator_create(prim);
        if (itr) {
        	for (p = iterator_first(itr); p; p = iterator_next(itr)) 
                	list_append(list, envar_dup(p));
                iterator_destroy(&itr);
        }
        return list;
}

