/* This file is part of GNU Radius.
   Copyright (C) 2004 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif
#include <stdio.h>
#ifdef HAVE_READLINE_READLINE_H
# include <readline/readline.h>
#endif
#include <common.h>
#include <radius/radius.h>	
#include <radtest.h>
#include "gram.h"

struct key_tab {
	char *name;
	int len;
	int tok;
	int initial;
};

static struct key_tab key_tab[] = {
	"auth",4,AUTH,0,
	"print",5,PRINT,1,
	"send",4,SEND,1,
	"exit",4,EXIT,1,
	"expect",6,EXPECT,1,
	"acct",4,ACCT,0,
	NULL
};

static char *
gen_state0_list(const char *text, int state)
{
	static int len;
	static struct key_tab *cursor;
	struct key_tab *kp;
	char *str;
	
	if (!state) {
		len = strlen(text);
		cursor = key_tab;
	}

	while ((kp = cursor++)->name) 
		if (kp->initial
		    && (len == 0
			|| (len <= strlen(kp->name)
			    && strncmp(kp->name, text, len) == 0)))
			return strdup(kp->name);
	return NULL;
}

static char *
gen_match_list(char *list[], const char *text, int state)
{
	static char **cursor;
	static int len;
	char *str;
	
	if (!state) {
		len = strlen(text);
		cursor = list;
	}
	
	while ((str = *cursor++)) 
		if (strlen (str) >= len && strncmp (str, text, len) == 0)
			return strdup (str);

	return NULL;
}

static char *
gen_literal_list(char *list[], int state)
{
	static char **cursor;

	if (!state)
		cursor = list;

	if (*cursor)
		return strdup(*cursor++);

	return NULL;
}

static char *
gen_number_list(const char *text, int state)
{
	static void *itr_data = NULL;
	const char *str;
	
	if (!state) 
		str = grad_first_matching_code_name(text, &itr_data);
	else 
		str = grad_next_matching_code_name(itr_data);
	if (!str) {
		grad_free(itr_data);
		return NULL;
	}
	return strdup(str);
}

static char *
gen_port_list(const char *text, int state)
{
	static char *names[] = { "auth", "acct", NULL };
	return gen_match_list(names, text, state);
}

struct dict_match {
	const char *text;
	int len;

	struct obstack stk;
	char *curp;
};

int
select_matching_attr(void *data, char const *name,
		     grad_dict_attr_t const *dict_entry ARG_UNUSED)
{
	struct dict_match *dm = data;
	if (strlen(name) >= dm->len && strncmp(name, dm->text, dm->len) == 0) 
		obstack_grow(&dm->stk, name, strlen(name)+1);
	return 0;
}

static char *
gen_attribute_name(const char *text, int state)
{
	static struct dict_match dict_match;
	if (!state) {
		obstack_init(&dict_match.stk);
		dict_match.text = text;
		dict_match.len = strlen(text);
		grad_dictionary_iterate(select_matching_attr, &dict_match);
		obstack_1grow(&dict_match.stk, 0);
		dict_match.curp = obstack_finish(&dict_match.stk);
	}
	if (*dict_match.curp) {
		char *ret = strdup(dict_match.curp);
		dict_match.curp += strlen(dict_match.curp) + 1;
		return ret;
	}
	obstack_free(&dict_match.stk, NULL);
	return NULL;
}

static int attribute_number;

int
select_matching_value(void *data, grad_dict_value_t *val)
{
	struct dict_match *dm = data;
	if (val->attr->value == attribute_number
	    && strlen(val->name) >= dm->len
	    && strncmp(val->name, dm->text, dm->len) == 0) 
		obstack_grow(&dm->stk, val->name, strlen(val->name)+1);
	return 0;
}

static char *
gen_attribute_value(const char *text, int state)
{
	static struct dict_match dict_match;
	if (!state) {
		obstack_init(&dict_match.stk);
		dict_match.text = text;
		dict_match.len = strlen(text);
		grad_dictionary_value_iterate(select_matching_value,
					      &dict_match);
		obstack_1grow(&dict_match.stk, 0);
		dict_match.curp = obstack_finish(&dict_match.stk);
	}
	if (*dict_match.curp) {
		char *ret = strdup(dict_match.curp);
		dict_match.curp += strlen(dict_match.curp) + 1;
		return ret;
	}
	obstack_free(&dict_match.stk, NULL);
	return NULL;
}

static int
is_cmp_op(char *str)
{
	switch (str[0]) {
	case '=':
		return str[1] == 0;
		
	case '<':
	case '>':
		return str[1] == 0 || str[1] == '=';
	}
	return 0;
}

char **
radtest_command_completion(char *text, int start, int end)
{
	struct key_tab *prev;
	if (start == 0) 
		return rl_completion_matches(text, gen_state0_list);
	else {
		int rc;
		int argc;
		char **argv;
		char *buf = grad_emalloc (start);
		memcpy(buf, rl_line_buffer, start);
		buf[start-1] = 0;
		
		rc = argcv_get(buf, "=", "#", &argc, &argv);

		grad_free(buf);
		
		if (rc)
			return NULL;

		if (strcmp (argv[argc-1], "send") == 0)
			return rl_completion_matches(text, gen_port_list);
		else if (strcmp (argv[argc-1], "auth") == 0
			 || strcmp (argv[argc-1], "acct") == 0)
			return rl_completion_matches(text, gen_number_list);
		else if (argc == 2 && strcmp (argv[argc-2], "expect") == 0)
			return rl_completion_matches(text, gen_attribute_name);
		else if (argc > 2) {
			if (strcmp (argv[argc-2], "auth") == 0
			    || strcmp (argv[argc-2], "acct") == 0
			    || is_cmp_op(argv[argc-2]))
				return rl_completion_matches(text,
							  gen_attribute_name);
			else if (is_cmp_op(argv[argc-1])) {
				grad_dict_attr_t *dict =
					grad_attr_name_to_dict(argv[argc-2]);
				if (!dict)
					return NULL;
				attribute_number = dict->value;
				return rl_completion_matches(text,
							  gen_attribute_value);
			}
		}
	}
			
				     
	return NULL;
}