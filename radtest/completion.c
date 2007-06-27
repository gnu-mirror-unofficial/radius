/* This file is part of GNU Radius.
   Copyright (C) 2004, 2005, 2007 Free Software Foundation, Inc.

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
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif

#ifdef WITH_READLINE

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
	{ "auth",  4, AUTH,    0 },
	{ "print", 5, PRINT,   1 },
	{ "send",  4, SEND,    1 },
	{ "exit",  4, EXIT,    1 },
	{ "expect",6, EXPECT,  1 },
	{ "acct",  4, ACCT,    0 },
	{ "begin", 5, T_BEGIN, 0 },
	{ "end",   3, T_END,   0 },
	{ "while", 5, WHILE,   1 },
	{ "do",    2, DO,      1 },
	{ "break", 5, BREAK,   1 },
	{ "continue", 8, CONTINUE, 1 },
	{ "if",    2, IF,      1 },
	{ "else",  4, ELSE,    1 },
	{ "set",   3, SET,     1 },
	{ "getopt",6, GETOPT,  0 },
	{ "input", 5, INPUT,   1 },
	{ "shift", 5, SHIFT,   1 },
	{ "return",6, T_RETURN,1 },
	{ "case",  4, CASE,    1 },
	{ "in",    2, IN,      0 },
	{ NULL }
};

static char *
gen_state0_list(const char *text, int state)
{
	static int len;
	static struct key_tab *cursor;
	struct key_tab *kp;
	
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


static struct obstack var_stk;
static char **namelist;

static char *
gen_variable_name(const char *text, int state)
{
	if (*namelist)
		return strdup(*(namelist++));
	return NULL;
}

struct varname_buf {
	char *ptr;
	size_t len;
};

int
variable_selector(void *data, grad_symbol_t *sym)
{
	struct varname_buf *vb = data;
	if (strlen(sym->name) >= vb->len
	    && strncmp(sym->name, vb->ptr, vb->len) == 0)
		obstack_grow(&var_stk, sym->name, strlen(sym->name)+1);
	return 0;
}
	    
char **
complete_variable(int start, int end)
{
	char **retval;
	char *p;
	struct varname_buf d;
	
	d.ptr = rl_line_buffer+start;
	d.len = end - start;

	obstack_init(&var_stk);
	grad_symtab_iterate(vartab, variable_selector, &d);
	obstack_1grow(&var_stk, 0);
	for (p = obstack_finish(&var_stk); *p; p += strlen(p)+1) 
		obstack_grow(&var_stk, &p, sizeof(char**));
	p = NULL;
	obstack_grow(&var_stk, &p, sizeof(char**));
	namelist = obstack_finish(&var_stk);
	retval = rl_completion_matches(rl_line_buffer, gen_variable_name);
	obstack_free(&var_stk, NULL);
	return retval;
}

char **
radtest_command_completion(char *text, int start, int end)
{
	if (start == 0) 
		return rl_completion_matches(text, gen_state0_list);
	else {
		int rc;
		int argc;
		char **argv;
		char *buf = grad_emalloc (start);
		memcpy(buf, rl_line_buffer, start);
		buf[start-1] = 0;
		
		rc = grad_argcv_get(buf, "=", "#", &argc, &argv);

		grad_free(buf);
		
		if (rc)
			return NULL;

		if (start > 1
		    && rl_line_buffer[start-1] == '$' 
		    && !isspace(rl_line_buffer[end]))
		    return complete_variable(start, end);
		
		if (strcmp (argv[argc-1], "send") == 0)
			return rl_completion_matches(text, gen_port_list);
		else if (strcmp (argv[argc-1], "auth") == 0
			 || strcmp (argv[argc-1], "acct") == 0
			 || (argc == 1 && strcmp (argv[0], "expect") == 0))
			return rl_completion_matches(text, gen_number_list);
		else if (argc == 2 && strcmp (argv[0], "expect") == 0)
			return rl_completion_matches(text,
						     gen_attribute_name);
		
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
			} else if (strcmp (argv[0], "expect") == 0)
				return rl_completion_matches(text,
							     gen_attribute_name);
		} 
	}
			
				     
	return NULL;
}

#else /* !WITH_READLINE */

char **
radtest_command_completion(char *text ARG_UNUSED, int start ARG_UNUSED,
			   int end ARG_UNUSED)
{
	return 0;
}

#endif /* WITH_READLINE */
