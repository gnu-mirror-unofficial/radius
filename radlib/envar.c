/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <mem.h>
#include <envar.h>

static void
envar_parse_internal(str, phead, ptail)
	char *str;
	envar_t **phead;
	envar_t **ptail;
{
	int i;
	int argc;
	char **argv;
	envar_t *head = NULL, *tail;

	*phead = *ptail = NULL;
	if (argcv_get(str, ",", &argc, &argv)) {
		if (argv)
			argcv_free(argc, argv);
		return NULL;
	}

	for (i = 0; i < argc; i++) {
		envar_t *env;
		char *p;
		
		if (argv[i][0] == ',')
			continue;
		env = alloc_entry(sizeof(*env));
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
		if (!head)
			head = env;
		else
			tail->next = env;
		tail = env;
	}

	argcv_free(argc, argv);
	*phead = head;
	*ptail = tail;
}

envar_t *
envar_parse(str)
	char *str;
{
	envar_t *head, *tail;
	envar_parse_internal(str, &head, &tail);
	return head;
}

envar_t *
envar_parse_argcv(argc, argv)
	int argc;
	char **argv;
{
	envar_t *head = NULL, *tail;
	while (argc--) {
		envar_t *ph, *pt;
		envar_parse_internal(*argv++, &ph, &pt);
		if (!head)
			head = ph;
		else
			tail->next = ph;
		tail = pt;
	}
	return head;
}

void
envar_free(env)
	envar_t *env;
{
	efree(env->name);
	efree(env->value);
}

void
envar_free_list(env)
	envar_t *env;
{
	free_slist((struct slist*)env, envar_free);
}

char *
envar_lookup(env, name)
	envar_t *env;
	char *name;
{
	for (; env; env = env->next) {
		if (strcmp(env->name, name) == 0)
			return env->value;
	}
	return NULL;
}

envar_t *
envar_dup(env)
	envar_t *env;
{
	envar_t *ep;

	ep = alloc_entry(sizeof(*ep));
	ep->name  = estrdup(env->name);
	ep->value = estrdup(env->value);
	return ep;
}

envar_t *
envar_merge_lists(prim, sec)
	envar_t *prim;
	envar_t *sec;
{
	envar_t *list, *p;

	list = NULL;
	for (; sec; sec = sec->next)
		if (!envar_lookup(prim, sec->name)) {
			p = envar_dup(sec);
			p->next = list;
			list = p;
		}
	for (; prim; prim = prim->next) {
		p = envar_dup(prim);
		p->next = list;
		list = p;
	}
	return list;
}

