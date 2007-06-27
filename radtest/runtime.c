/* This file is part of GNU Radius.
   Copyright (C) 2004,2005,2007 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <setjmp.h>

#include <common.h>
#include <radius/radargp.h>
#include <radtest.h>
#include <radius/argcv.h>

static jmp_buf errbuf;      /* Buffer for jumping to from the error state */
static int break_level;     /* Break (continue) from that many loops */
static int continue_loop;   /* 1 if we are continuing */
static radtest_variable_t function_result; /* Result of the last executed
					      function */
static grad_list_t *curenv; /* Current environment */ 

/* Forward declarations */
static void rt_eval_stmt_list(grad_list_t *list);
static void rt_eval_expr(radtest_node_t *node, radtest_variable_t *result);
static void rt_eval(radtest_node_t *stmt);
static void rt_eval_variable(grad_locus_t *locus,
			     radtest_variable_t *result,
			     radtest_variable_t *var);
static char *cast_to_string(grad_locus_t *locus, radtest_variable_t const *var);

/* Runtime error handling */
static void
runtime_error(grad_locus_t *locus, const char *fmt, ...)
{
	va_list ap;

	if (locus)
		fprintf(stderr, "%s:%d: ",
			locus->file, locus->line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	longjmp(errbuf, 1);
}

void
var_asgn(radtest_variable_t *var, radtest_variable_t *result)
{
	var->type = result->type;

	switch (result->type) {
        case rtv_undefined:
        case rtv_integer:
        case rtv_ipaddress:
		var->datum = result->datum;
		break;

	case rtv_bstring:
		var->datum.bstring.ptr = grad_emalloc(result->datum.bstring.length);
		memcpy(var->datum.bstring.ptr, result->datum.bstring.ptr,
		       result->datum.bstring.length);
		var->datum.bstring.length = result->datum.bstring.length;
		break;
		
        case rtv_string:
		/* FIXME: memory leak */
		var->datum.string = grad_estrdup(result->datum.string);
		break;
		
	case rtv_avl:
		var->datum.avl = result->datum.avl;
		break;
		
        case rtv_pairlist:
		grad_insist_fail("rtv_pairlist in assignment");
		
	default:
		grad_insist_fail("invalid data type in assignment");
	}
}


/* Radtest environment */

void
radtest_env_add_string(grad_list_t *env, char *string)
{
	radtest_variable_t *var;
	var = grad_emalloc(sizeof(*var));
	var->type = rtv_string;
	var->datum.string = string;
	grad_list_append(env, var);
}

void
radtest_env_add(grad_list_t *env, radtest_variable_t *var)
{
	grad_list_append(env, var);
}

radtest_variable_t *
radtest_env_get(grad_list_t *env, int n)
{
	return grad_list_item(env, n);
}

int
radtest_env_shift(grad_list_t *env, int amount)
{
	if (amount > grad_list_count(env)-1)
		return 1;
	while (amount--)
		grad_list_remove(env, grad_list_item(env, 1), NULL);
	return 0;
}

void
radtest_env_to_argv(grad_list_t *env, grad_locus_t *locus,
		    int *pargc, char ***pargv)
{
	int i, argc;
	char **argv;

	argc = grad_list_count(env);
	argv = calloc(argc + 1, sizeof (char *));
	if (!argv)
		runtime_error(locus, _("out of memory"));
	for (i = 0; i < argc; i++) {
		radtest_variable_t *var = grad_list_item(env, i);
		char *p = cast_to_string(locus, var);
		argv[i] = malloc(strlen(p) + 1);
		if (!argv[i])
			runtime_error(locus, _("out of memory"));
		strcpy(argv[i], p);
	}
	argv[i] = NULL;

	*pargc = argc;
	*pargv = argv;
}
		
	

/* Main entry point */

int
radtest_eval(radtest_node_t *stmt, grad_list_t *env)
{
	if (setjmp(errbuf))
		return 1;
	break_level = continue_loop = 0;
	curenv = env;
	rt_eval(stmt);
	return 0;
}


#define RT_EVAL(locus,result,op,a,b) \
	switch (op) {                               \
	case radtest_op_add:                        \
		result->datum.number = a + b;       \
		break;                              \
		                                    \
	case radtest_op_sub:                        \
		result->datum.number = a - b;       \
		break;                              \
                                                    \
	case radtest_op_mul:                        \
		result->datum.number = a * b;       \
		break;                              \
		                                    \
	case radtest_op_div:                        \
                if (b == 0)                         \
                   runtime_error(locus, _("division by zero")); \
          	result->datum.number = a / b;       \
		break;                              \
		                                    \
	case radtest_op_mod:                        \
                if (b == 0)                         \
                   runtime_error(locus, _("division by zero")); \
		result->datum.number = a % b;       \
		break;                              \
		                                    \
	case radtest_op_and:                        \
		result->datum.number = a & b;       \
		break;                              \
		                                    \
	case radtest_op_or:                         \
		result->datum.number = a | b;       \
		break;                              \
		                                    \
	case radtest_op_eq:                         \
		result->datum.number = a == b;      \
		break;                              \
		                                    \
	case radtest_op_ne:                         \
		result->datum.number = a != b;      \
		break;                              \
                                                    \
	case radtest_op_lt:                         \
		result->datum.number = a < b;       \
		break;                              \
		                                    \
	case radtest_op_le:                         \
		result->datum.number = a <= b;      \
		break;                              \
		                                    \
	case radtest_op_gt:                         \
		result->datum.number = a > b;       \
		break;                              \
		                                    \
	case radtest_op_ge:                         \
		result->datum.number = a >= b;      \
		break;                              \
	}

static void
rt_eval_bin_int(grad_locus_t *locus,
		radtest_variable_t *result, radtest_binop_t op, long a, long b)
{
	result->type = rtv_integer;
	RT_EVAL(locus, result, op, a, b);
}

static void
rt_eval_bin_uint(grad_locus_t *locus,
		 radtest_variable_t *result, radtest_binop_t op,
		 grad_uint32_t a, grad_uint32_t b)
{
	result->type = rtv_ipaddress;
	RT_EVAL(locus, result, op, a, b);
}

static char *binop_string[] = {
/* TRANSLATORS: The following operation names are used as complements,
   e.g.: "incompatible types in addition"
*/
	N_("addition"),
	N_("subtraction"),
	N_("multiplication"),
	N_("division"),
	N_("division"),
	N_("boolean conjunction"),
	N_("boolean disjunction"),
	N_("comparison"),
	N_("comparison"),
	N_("comparison"),
	N_("comparison"),
	N_("comparison"),
	N_("comparison")
};

static void
bin_type_error(grad_locus_t *locus, radtest_binop_t op)
{
	runtime_error(locus, _("incompatible types in %s"),
		      gettext(binop_string[op]));
}

/* TRANSLATORS: The following operation names are used as complements,
   e.g.: "incompatible type in binary negation"
*/
static char *unary_string[] = {
	N_("binary negation"),
	N_("numeric negation"),
};

static void
unary_type_error(grad_locus_t *locus, radtest_unop_t op)
{
	runtime_error(locus,
		      _("incompatible data type in %s"),
		      gettext(unary_string[op]));
}

static void
rt_eval_bin_str(grad_locus_t *locus,
		radtest_variable_t *result, radtest_binop_t op,
		char *a, char *b)
{
	switch (op) {
	case radtest_op_add:
		radtest_start_string(a);
		radtest_add_string(b);
		result->type = rtv_string;
		result->datum.string = radtest_end_string();
		break;

	case radtest_op_eq:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) == 0;
		break;
		
	case radtest_op_ne:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) != 0;
		break;
		
	case radtest_op_lt:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) < 0;
		break;

	case radtest_op_le:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) <= 0;
		break;

	case radtest_op_gt:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) > 0;
		break;

	case radtest_op_ge:
		result->type = rtv_integer;
		result->datum.number = strcmp(a, b) >= 0;
		break;
		
	default:
		bin_type_error(locus, op);
	}
}

static int
_found_p(void *data, grad_avp_t *pair)
{
	return grad_avl_find(data, pair->attribute) != NULL;
}				

static int
_not_found_p(void *data, grad_avp_t *pair)
{
	return grad_avl_find(data, pair->attribute) == NULL;
}				

void
rt_eval_bin_avl(grad_locus_t *locus,
		radtest_variable_t *result,
		radtest_binop_t op,
		grad_avp_t *a, grad_avp_t *b)
{
	switch (op) {
	case radtest_op_add:
		grad_avl_merge(&a, &b);
		grad_avl_free(b);
		result->type = rtv_avl;
		result->datum.avl = a;
		break;
		
	case radtest_op_sub:
		result->type = rtv_avl;
		result->datum.avl = NULL;
		grad_avl_move_pairs(&result->datum.avl,
				    &a,
				    _not_found_p,
				    b);
		break;
		
	case radtest_op_mod:
		/* Return the intersection of A and B */
		result->type = rtv_avl;
		result->datum.avl = NULL;
		grad_avl_move_pairs(&result->datum.avl,
				    &a,
				    _found_p,
				    b);
		break;
		
	case radtest_op_eq:
		result->type = rtv_integer;
		result->datum.number = compare_lists(a, b) == 0;
		break;
		
	case radtest_op_ne:
		result->type = rtv_integer;
		result->datum.number = compare_lists(a, b) != 0;
		break;

	default:
		bin_type_error(locus, op);
	}
}

static void
rt_eval_deref(radtest_node_t *node, radtest_variable_t *result)
{
	radtest_datum_t datum;
	size_t n;
	radtest_variable_t *var;
	char *p;
		
	var = (radtest_variable_t*) grad_sym_lookup(vartab,
						    node->v.deref.name);
	if (var && var->type != rtv_undefined) {
		rt_eval_variable(&node->locus, result, var);
		return;
	}

	result->type = rtv_undefined;

	p = node->v.deref.repl;
	if (p) switch (*p++) {
        case '=':
		if (!var)
			var = (radtest_variable_t*)
				grad_sym_install(vartab, node->v.deref.name);
                var->type = parse_datum(p, &var->datum);
		radtest_var_copy(result, var);
                break;
                
        case '-':
                switch (result->type = parse_datum(p, &datum)) {
                case rtv_undefined:
                        runtime_error(&node->locus,
				      _("variable `%s' used before definition"),
				      node->v.deref.name);
                        break;
                        
                case rtv_integer:
                case rtv_ipaddress:
		case rtv_string:
			result->datum = datum;
			break;

		default:
			runtime_error(&node->locus,
				      _("%s:%d: unknown data type"),
				      __FILE__, __LINE__);
		}
                break;
		
        case '?':
                if (*p) 
                        fprintf(stderr, "%s\n", p);
                else
                        fprintf(stderr, "%s: variable unset\n",
				node->v.deref.name);
                exit(1);
                                
        case ':':
                if (*p)
                        printf("%s", p);
                else
                        printf("(%s:%lu)%s? ",
                               node->locus.file,
                               (unsigned long)node->locus.line,
                               node->v.deref.name);
                p = NULL;
                n = 0;
                getline(&p, &n, stdin);
		result->type = rtv_string;
		radtest_start_string(p);
                result->datum.string = radtest_end_string();
		free(p);
                break;
                
        case '&':
                if (!*p)
                        asprintf(&p, "(%s:%lu)%s? ",
                                 node->locus.file,
                                 node->locus.line,
                                 node->v.deref.name);
                p = getpass(p);
                if (!p)
                        exit(0);
		result->type = rtv_string;
		radtest_start_string(p);
                result->datum.string = radtest_end_string();
                break;
        }
	if (result->type == rtv_undefined)
		runtime_error(&node->locus,
			      _("variable `%s' used before definition"),
			      node->v.deref.name);
}

static void
rt_eval_parm(radtest_node_t *node, radtest_variable_t *result)
{
	int num = node->v.parm.number;
	char *p;
	size_t n;
	radtest_variable_t *var;
	
	var = radtest_env_get(curenv, num);
	if (var) {
		rt_eval_variable(&node->locus, result, var);
		return;
	}
        
        if (!node->v.parm.repl) {
		radtest_start_string("");
		result->type = rtv_string;
		result->datum.string = radtest_end_string();
                return;
        }
        p = node->v.parm.repl;
	
        switch (*p++) {
        case '=':
		radtest_start_string(p);
		var->type = rtv_string;
		var->datum.string = radtest_end_string();
		radtest_env_add(curenv, var);
		radtest_var_copy(result, var);
                break;
                
        case '-':
		radtest_start_string(p);
		result->type = rtv_string;
		result->datum.string = p;
                break;
                
        case '?':
                if (*p) 
                        fprintf(stderr, "%s\n", p);
                else
                        fprintf(stderr, "parameter %d unset\n", num);
                exit(1);
                                
        case ':':
                if (*p)
                        printf("%s", p);
                else
                        printf("(%s:%lu)%d? ",
                               node->locus.file,
                               (unsigned long) node->locus.line,
                               num);
                p = NULL;
                n = 0;
                getline(&p, &n, stdin);
		radtest_start_string(p);
		result->type = rtv_string;
		result->datum.string = radtest_end_string();
                free(p);
                break;
                
        case '&':
                if (!*p)
                        asprintf(&p, "(%s:%lu)%d? ",
                                 node->locus.file,
                                 (unsigned long) node->locus.line,
                                 num);
                p = getpass(p);
                if (!p)
                        exit(0);
		radtest_start_string(p);
		result->type = rtv_string;
		result->datum.string = radtest_end_string();
                break;
        }
}

static void
rt_eval_pairlist(grad_locus_t *locus,
		 radtest_variable_t *result, radtest_variable_t *var)
{
	grad_avp_t *plist = NULL;
	radtest_pair_t *p;
	grad_iterator_t *itr = grad_iterator_create(var->datum.list);
	
	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) {
		radtest_variable_t val;
		grad_avp_t *pair = NULL;
		grad_uint32_t n;
		char buf[64];
		
		rt_eval_expr(p->node, &val);
		switch (val.type) {
		default:
			grad_insist_fail("invalid data type in "
					 "rt_eval_pairlist");
			
		case rtv_pairlist:
		case rtv_avl:
			runtime_error(locus, _("invalid data type"));
			break;
			
		case rtv_integer:
			switch (p->attr->type) {
			case GRAD_TYPE_STRING:
			case GRAD_TYPE_DATE:
				snprintf(buf, sizeof buf, "%ld",
					 val.datum.number);
				pair = grad_avp_create_string(p->attr->value,
							      buf);
				break;
				
			case GRAD_TYPE_INTEGER:
			case GRAD_TYPE_IPADDR:
				pair = grad_avp_create_integer(p->attr->value,
							       val.datum.number);
				break;
			}
			break;
			
		case rtv_ipaddress:
			switch (p->attr->type) {
			case GRAD_TYPE_STRING:
			case GRAD_TYPE_DATE:
				snprintf(buf, sizeof buf, "%lu",
					 (unsigned long) val.datum.ipaddr);
				pair = grad_avp_create_string(p->attr->value,
							      buf);
				break;
				
			case GRAD_TYPE_INTEGER:
			case GRAD_TYPE_IPADDR:
				pair = grad_avp_create_integer(p->attr->value,
							       val.datum.ipaddr);
				break;
			}
			break;

		case rtv_bstring:
			switch (p->attr->type) {
			case GRAD_TYPE_STRING:
				pair = grad_avp_create_binary(p->attr->value,
							      val.datum.bstring.length,
							      val.datum.bstring.ptr);
				break;

			default:
				/* FIXME */
				runtime_error(locus, _("invalid data type"));
			}
			break;
			
		case rtv_string:
			switch (p->attr->type) {
			case GRAD_TYPE_STRING:
			case GRAD_TYPE_DATE:
				pair = grad_avp_create_string(p->attr->value,
							      val.datum.string);
				break;
				
			case GRAD_TYPE_INTEGER:
			{
				grad_dict_value_t *dv =
				    grad_value_name_to_value(val.datum.string,
							     p->attr->value);
				if (dv) {
					pair = grad_avp_create_integer(
						   p->attr->value,
						   dv->value);
					break;
				}
			}
			/*FALLTHROUGH*/
					
			case GRAD_TYPE_IPADDR:
				/*FIXME: error checking*/
				n = strtoul(val.datum.string, NULL, 0);
				pair = grad_avp_create_integer(p->attr->value,
							       n);
				break;
			}
			break;
		}
		grad_insist(pair != NULL);
		grad_avl_merge(&plist, &pair);
		grad_avp_free(pair);
	}
	grad_iterator_destroy(&itr);

	result->type = rtv_avl;
	result->datum.avl = plist;
}
	
static void
rt_eval_variable(grad_locus_t *locus,
		 radtest_variable_t *result, radtest_variable_t *var)
{
	switch (var->type) {
	case rtv_pairlist:
		rt_eval_pairlist(locus, result, var);
		break;

	case rtv_avl:
		result->type = var->type;
		result->datum.avl = grad_avl_dup(var->datum.avl);
		break;
		
	default:
		*result = *var;
	}
}

static void
rt_eval_call(radtest_node_t *stmt, radtest_variable_t *result)
{
	grad_list_t *env, *tmp;
	grad_iterator_t *itr;
	radtest_node_t *expr;
	radtest_variable_t *var;
	
	env = grad_list_create();
	var = radtest_var_alloc(rtv_string);
	var->datum.string = stmt->v.call.fun->name;
	radtest_env_add(env, var);
	
	itr = grad_iterator_create(stmt->v.call.args);
	for (expr = grad_iterator_first(itr);
	     expr;
	     expr = grad_iterator_next(itr)) {
		radtest_variable_t result;

		rt_eval_expr(expr, &result);
		radtest_env_add(env, radtest_var_dup(&result));
	}
	grad_iterator_destroy(&itr);

	tmp = curenv;
	curenv = env;
	function_result.type = rtv_undefined;
	rt_eval_stmt_list(stmt->v.call.fun->body);

	grad_list_destroy(&env, NULL, NULL);
	
	curenv = tmp;
	if (result)
		*result = function_result;
	break_level = 0;
}

static char *type_string[] = {
/* TRANSLATORS: The following six msgids are data type names in the
   form of *direct object*. They are used in place of the first %s
   in the sentence 'cannot convert %s %s' */
	N_("undefined"),
	N_("integer"),
	N_("ipaddress"),
	N_("string"),
	N_("binary string"),
	N_("pairlist"),
	N_("A/V list")
};

static char *type_string_to[] = {
/* TRANSLATORS: The following six msgids are data type names in the
   form of *indirect object*. They are used in place of second %s
   in the sentence 'cannot convert %s %s' */
	N_("to undefined"),
	N_("to integer"),
	N_("to ipaddress"),
	N_("to string"),
	N_("to binary string"),
	N_("to pairlist"),
	N_("to A/V list")
};

static void
typecast_error(grad_locus_t *locus, radtest_data_type from,
	       radtest_data_type to)
{
	runtime_error(locus,
/* TRANSLATORS: First %s is replaced with a type name,
   second %s -- with a type name with an appropriate preposition.
   For example, in English:
     cannot convert integer to string
*/
		      _("cannot convert %s %s"),
		      gettext(type_string[from]),
		      gettext(type_string_to[to]));
}

typedef int (*typecast_proc_t) (radtest_variable_t *);

static int
tc_error(radtest_variable_t *var ARG_UNUSED)
{
	return 1;
}

static int
int_to_ip(radtest_variable_t *var)
{
	var->datum.ipaddr = var->datum.number;
	var->type = rtv_ipaddress;
	return 0;
}

static int
ip_to_int(radtest_variable_t *var)
{
	var->datum.number = var->datum.ipaddr;
	return 0;
}

static int
int_to_str(radtest_variable_t *var)
{
	static char buf[64];
	
	snprintf(buf, sizeof buf, "%ld", var->datum.number);
	radtest_start_string(buf);
	var->datum.string = radtest_end_string();
	var->type = rtv_string;
	return 0;
}

static int
ip_to_str(radtest_variable_t *var)
{
	radtest_start_string(grad_ip_iptostr(var->datum.ipaddr, NULL));
	var->datum.string = radtest_end_string();
	var->type = rtv_string;
	return 0;
}

static int
str_to_int(radtest_variable_t *var)
{
	long v;
	
	if (isdigit(var->datum.string[0])) {
		char *p;
		v = strtol(var->datum.string, &p, 0);
		if (*p)
			return 1;
	} else if ((v = grad_request_name_to_code(var->datum.string)) == 0)
		return 1;
	var->datum.number = v;
	var->type = rtv_integer;
	return 0;
}

static int
str_to_ip(radtest_variable_t *var)
{
	/* FIXME: no error checking */
	var->datum.ipaddr = grad_ip_gethostaddr(var->datum.string);
	var->type = rtv_ipaddress;
	return 0;
}

typecast_proc_t typecast_proc[][RTV_MAX] = {
        /* undefined   integer   ipaddress     string    bstring  pairlist  avl */
/* und */ { tc_error,  tc_error,  tc_error,   tc_error,  tc_error, tc_error, tc_error },
/* int */ { tc_error,      NULL, int_to_ip, int_to_str,  tc_error, tc_error, tc_error },
/* ip  */ { tc_error, ip_to_int,      NULL,  ip_to_str,  tc_error, tc_error, tc_error },
/* str */ { tc_error,str_to_int, str_to_ip,       NULL,  tc_error, tc_error, tc_error },
/* bstr*/ { tc_error,  tc_error,  tc_error,   tc_error,      NULL, tc_error, tc_error },
/* pls */ { tc_error,  tc_error,  tc_error,   tc_error,  tc_error, tc_error, tc_error },
/* avl */ { tc_error,  tc_error,  tc_error,   tc_error,  tc_error, tc_error, tc_error },
};

static int
try_typecast(radtest_variable_t *var, radtest_data_type t)
{
	typecast_proc_t proc = typecast_proc[var->type][t];
	return proc && proc(var);
}

static void
typecast(grad_locus_t *locus, radtest_variable_t *var, radtest_data_type t)
{
	if (try_typecast(var, t))
		typecast_error(locus, var->type, t);
}

static char *
cast_to_string(grad_locus_t *locus, radtest_variable_t const *var)
{
	static char buf[64];
	
	switch (var->type) {
	case rtv_string:
		return var->datum.string;
		
	case rtv_integer:
		snprintf(buf, sizeof buf, "%ld", var->datum.number);
		break;
			
	case rtv_ipaddress:
		grad_ip_iptostr(var->datum.ipaddr, buf);
		break;
		
	default:
		typecast_error(locus, var->type, rtv_string);
	}
	return buf;
}

static int
cast_to_boolean(grad_locus_t *locus, radtest_variable_t const *var)
{
	switch (var->type) {
	case rtv_string:
		return var->datum.string[0];
		
	case rtv_integer:
		return var->datum.number;
			
	case rtv_ipaddress:
		return var->datum.ipaddr != 0;
		break;

	case rtv_avl:
		return var->datum.avl != NULL;
		break;
		
	default:
		typecast_error(locus, var->type, rtv_string);
	}
	return 0;
}

static int
strnum_p(radtest_variable_t *var)
{
	char *p;
	if (var->type != rtv_string)
		return 0;
	for (p = var->datum.string; *p; p++)
		if (!isspace(*p))
			break;
	if (!*p)
		return 0;
	if (*p == '+' || *p == '-')
		p++;
	for (; *p; p++)
		if (!isdigit(*p))
			return 0;
	return 1;
}

static int
number_p(radtest_variable_t *var)
{
	return var->type == rtv_integer || var->type == rtv_ipaddress;
}

static void
rt_eval_expr(radtest_node_t *node, radtest_variable_t *result)
{
	radtest_variable_t left, right;

	if (!node) {
		result->type = rtv_undefined;
		return;
	}
	
	switch (node->type) {
	case radtest_node_value:
		rt_eval_variable(&node->locus, result, node->v.var);
		break;
		
	case radtest_node_bin:
		rt_eval_expr(node->v.bin.left, &left);

		/* Boolean shortcut */
		if (node->v.bin.op == radtest_op_and
		    || node->v.bin.op == radtest_op_or) {
			result->type = rtv_integer;
			result->datum.number = node->v.bin.op == radtest_op_or;
			if (cast_to_boolean(&node->locus, &left)
			    == result->datum.number) 
				break;
		}
		
		rt_eval_expr(node->v.bin.right, &right);
		
		if (left.type != right.type) {
			if (node->v.bin.left->type == radtest_node_value
			    && try_typecast(&right, left.type) == 0)
				/* nothing */;
			else if (node->v.bin.right->type == radtest_node_value
				 && try_typecast(&left, right.type) == 0)
				/* nothing */;
			else if (strnum_p(&left) && number_p(&right))
				typecast(&node->locus, &right, left.type);
			else if (strnum_p(&right) && number_p(&left))
				typecast(&node->locus, &left, right.type);
			else if (left.type == rtv_ipaddress
				 && right.type == rtv_integer)
				typecast(&node->locus, &right, left.type);
			else if (right.type == rtv_ipaddress
				 && left.type == rtv_integer)
				typecast(&node->locus, &left, right.type);
			else if (left.type == rtv_string)
				typecast(&node->locus, &right, left.type);
			else if (right.type == rtv_string)
				typecast(&node->locus, &left, right.type);
			else
				bin_type_error(&node->locus, node->v.bin.op);
		}
		grad_insist(left.type == right.type);
		switch (left.type) {
		case rtv_undefined:
			grad_insist_fail("bad datatype");
			
		case rtv_integer:
			rt_eval_bin_int(&node->locus,
					result,
					node->v.bin.op,
					left.datum.number,
					right.datum.number);
			break;

		case rtv_ipaddress:
			rt_eval_bin_uint(&node->locus,
					 result,
					 node->v.bin.op,
					 left.datum.number,
					 right.datum.ipaddr);
			break;
			
		case rtv_string:
			rt_eval_bin_str(&node->locus,
					result,
					node->v.bin.op,
					left.datum.string,
					right.datum.string);
			break;
				
		case rtv_pairlist:
			grad_insist_fail("a value cannot evaluate to "
					 "rtv_pairlist");

		case rtv_avl:
			rt_eval_bin_avl(&node->locus,
					result,
					node->v.bin.op,
					left.datum.avl,
					right.datum.avl);
			break;
		}
		break;
		
	case radtest_node_unary:
		rt_eval_expr(node->v.unary.operand, &left);
		switch (node->v.unary.op) {
		case radtest_op_neg:
			typecast(&node->locus, &left, rtv_integer);
			result->type = rtv_integer;
			result->datum.number = - left.datum.number;
			break;
			
		case radtest_op_not:
			switch (left.type) {
			case rtv_string:
				if (strnum_p(&left)) {
					typecast(&node->locus, &left, rtv_integer);
					/* FALL THROUGH */
				} else {
					result->datum.number =
						left.datum.string[0] == 0;
					break;
				}
						
			case rtv_integer:
				result->datum.number = ! left.datum.number;
				break;
				
			case rtv_ipaddress:
				typecast(&node->locus, &left, rtv_integer);
				result->datum.number = ! left.datum.number;
				break;
				
			case rtv_avl:
				result->datum.number = left.datum.avl == NULL;
				break;
					
			default:
				unary_type_error(&node->locus,
						 node->v.unary.op);
			}
			result->type = rtv_integer;
		}
		break;
			
	case radtest_node_deref:
		rt_eval_deref(node, result);
		break;
		
	case radtest_node_parm:
		rt_eval_parm(node, result);
		break;
		
	case radtest_node_attr:
	{
		grad_avp_t *p;
		
		rt_eval_expr(node->v.attr.node, &left);
		if (left.type != rtv_avl)
			runtime_error(&node->locus, _("not a pair list"));
		p = grad_avl_find(left.datum.avl, node->v.attr.dict->value);
		switch (node->v.attr.dict->type) {
		case GRAD_TYPE_STRING:
			result->type = rtv_string;
			if (node->v.attr.all) {
				size_t len = 1;
				for (p = left.datum.avl; p; p = p->next) {
					if (p->attribute ==
					          node->v.attr.dict->value)
						len += p->avp_strlength;
				}
				result->datum.string = grad_emalloc(len);
				result->datum.string[0] = 0;
				for (p = left.datum.avl; p; p = p->next) {
					if (p->attribute ==
					          node->v.attr.dict->value)
						strcat(result->datum.string,
						       p->avp_strvalue);
				}
			} else
				result->datum.string = p ?
					p->avp_strvalue : "";
			break;
			
		case GRAD_TYPE_DATE:    
			result->type = rtv_string;
			result->datum.string = p ? p->avp_strvalue : "";
			break;
			
		case GRAD_TYPE_INTEGER:
			result->type = rtv_integer;
			result->datum.number = p ? p->avp_lvalue : 0;
			break;
			
		case GRAD_TYPE_IPADDR:
			result->type = rtv_ipaddress;
			result->datum.number = p ? p->avp_lvalue : 0;
			break;
		}
		break;
	}
	
	case radtest_node_getopt:
	{
		char buf[3];

		if (node->v.gopt.last <= 0) {
			optind = 0;
			radtest_env_to_argv(curenv, &node->locus,
					    &node->v.gopt.argc,
					    &node->v.gopt.argv);
		}

		opterr = 0;
		node->v.gopt.last = getopt(node->v.gopt.argc,
					   node->v.gopt.argv,
					   node->v.gopt.optstr);
		result->type = rtv_integer;
		result->datum.number = node->v.gopt.last != EOF;

		if (node->v.gopt.last == EOF) 
			grad_argcv_free(node->v.gopt.argc, node->v.gopt.argv);

		node->v.gopt.var->type = rtv_string;
		grad_free(node->v.gopt.var->datum.string);
		sprintf(buf, "-%c",
			node->v.gopt.last == EOF ? '-'
			   : (node->v.gopt.last == '?' ? optopt
			        : node->v.gopt.last));
		node->v.gopt.var->datum.string = grad_estrdup(buf);

		grad_free(node->v.gopt.arg->datum.string);
		if (!optarg)
			node->v.gopt.arg->type = rtv_undefined;
		else {
			node->v.gopt.arg->type = rtv_string;
			node->v.gopt.arg->datum.string = grad_estrdup(optarg);
		}

		node->v.gopt.ind->type = rtv_integer;
		node->v.gopt.ind->datum.number = optind;
		break;
	}

	case radtest_node_argcount:
		result->type = rtv_integer;
		result->datum.number = grad_list_count(curenv) - 1;
		break;
	
	case radtest_node_call:
		rt_eval_call(node, result);
		break;
		
	default:
		grad_insist_fail("Unexpected node type");
	}
	
	var_asgn(grad_sym_lookup_or_install(vartab, "_", 1), result);
}

static int
_printer(void *item, void *data)
{
	radtest_variable_t result;
	rt_eval_expr(item, &result);
	var_print(&result);
	return 0;
}

static void
rt_print(grad_list_t *list)
{
	grad_list_iterate(list, _printer, NULL);
}

static void
rt_asgn(radtest_node_t *node)
{
	radtest_variable_t *var;
	radtest_variable_t result;
	
	rt_eval_expr(node->v.asgn.expr, &result);
	
	var = (radtest_variable_t*)
		grad_sym_lookup_or_install(vartab, node->v.asgn.name, 1);

	var_asgn(var, &result);
}

static void
rt_send(radtest_node_t *node)
{
	radtest_node_send_t *send = &node->v.send;
	grad_avp_t *avl = NULL;

	if (send->expr) {
		radtest_variable_t val;
		rt_eval_expr(send->expr, &val);
		if (val.type != rtv_avl)
			runtime_error(&node->locus,
				      _("invalid data type in send statement "
					"(expected A/V list)"));
		avl = val.datum.avl;
	}
	
	radtest_send(send->port_type, send->code, avl, send->cntl);
	grad_symtab_free(&send->cntl);
	grad_avl_free(avl);
}

static void
rt_expect(radtest_node_t *node)
{
	radtest_node_expect_t *exp = &node->v.expect;
	int pass = 1;
	if (verbose) {
		printf(_("expect %s\n"), grad_request_code_to_name(exp->code));
		printf(_("got    %s\n"), grad_request_code_to_name(reply_code));
	}
	if (reply_code != exp->code) 
		pass = 0;

	if (exp->expr) {
		radtest_variable_t result;
		rt_eval_expr(exp->expr, &result);
		if (result.type != rtv_avl)
			runtime_error(&node->locus,
				      _("expected A/V pair list"));
		if (compare_lists(reply_list, result.datum.avl))
			pass = 0;
		grad_avl_free(result.datum.avl);
	}
	printf("%s\n", pass ? "PASS" : "FAIL");
}

static void
rt_exit(radtest_node_t *expr)
{
	int code = 0;
	if (expr) {
		radtest_variable_t result;
		rt_eval_expr(expr, &result);
		switch (result.type) {
		case rtv_integer:
			code = result.datum.number;
			break;
			
		case rtv_string:
			/* FIXME: No error checking */
			code = strtoul(result.datum.string, NULL, 0);
			break;

		default:
			/* Use parse_error_loc() so we don't longjump */
			parse_error_loc(&expr->locus,
					_("invalid data type in exit statement"));
			break; /* exit anyway */
		}
	}
	exit(code);
}

static int
rt_true_p(radtest_variable_t *var)
{
	switch (var->type) {
	case rtv_integer:
		return var->datum.number;
		
	case rtv_ipaddress:
		return var->datum.ipaddr != 0;
		
	case rtv_string:
		return var->datum.string[0];
		
	case rtv_pairlist:
		return grad_list_count(var->datum.list) > 0;
		
	case rtv_avl:
		return var->datum.avl != NULL;

	default:
		grad_insist_fail("Unexpected data type");
	}
	return 0;
}

static void
rt_eval_loop(radtest_node_t *stmt)
{
	radtest_node_loop_t *loop = &stmt->v.loop;
	int restart;
	
	if (loop->first_pass)
		rt_eval(loop->body);

	do {
		radtest_variable_t result;

		restart = 0;
		while (break_level == 0) {
			rt_eval_expr(loop->cond, &result);
			if (!rt_true_p(&result))
				break;
			rt_eval(loop->body);
		}
		if (break_level) {
			break_level--;
			restart = continue_loop;
			continue_loop = 0;
		}
	} while (restart);
}

static void
rt_eval_input(radtest_node_t *stmt)
{
	char *p = NULL;
	size_t n = 0;
	radtest_variable_t *var;

	if (stmt->v.input.expr) {
		radtest_variable_t result;
		rt_eval_expr(stmt->v.input.expr, &result);
		printf("%s", cast_to_string(&stmt->locus, &result));
	}
	fflush(stdout);
		
	getline(&p, &n, stdin);
	var = stmt->v.input.var;

	switch (var->type) {
	case rtv_string:
		grad_free(var->datum.string);
		break;

	case rtv_avl:
		grad_avl_free(var->datum.avl);
		break;

	default:
		break;
	}
	
	var->type = rtv_string;
	n = strlen(p);
	if (n > 1 && p[n-1] == '\n')
		p[n-1] = 0;
	var->datum.string = grad_estrdup(p);
	free(p);
}

static void
rt_eval_case(radtest_node_t *stmt)
{
	radtest_variable_t result;
	char *sample;
	grad_iterator_t *itr;
	radtest_case_branch_t *bp;
	
	rt_eval_expr(stmt->v.branch.expr, &result);
	sample = cast_to_string(&stmt->locus, &result);
	radtest_start_string(sample);
	sample = radtest_end_string();
	
	itr = grad_iterator_create(stmt->v.branch.branchlist);
	for (bp = grad_iterator_first(itr);
	     bp;
	     bp = grad_iterator_next(itr)) {
		char *p;
		regex_t rx;
		int rc;
		
		rt_eval_expr(bp->cond, &result);
		p = cast_to_string(&bp->cond->locus, &result);

                /* FIXME: configurable flags */
		rc = regcomp(&rx, p, REG_EXTENDED);

		if (rc) {
			char errbuf[512];
			regerror(rc, &rx, errbuf, sizeof(errbuf));
			runtime_error(&bp->cond->locus, "%s", errbuf);
		}

		rc = regexec(&rx, sample, 0, NULL, 0);
		regfree(&rx);
		if (rc == 0) {
			rt_eval(bp->node);
			break;
		}
	}
	grad_iterator_destroy(&itr);
}

static void
rt_eval(radtest_node_t *stmt)
{
	radtest_variable_t result;

	if (!stmt)
		return;
	
	if (break_level) 
		return;
	
	switch (stmt->type) {
		
	case radtest_node_stmt:
		rt_eval_stmt_list(stmt->v.list);
		break;
		
	case radtest_node_print:
		rt_print(stmt->v.list);
		break;
		
	case radtest_node_asgn:
		rt_asgn(stmt);
		break;
		
	case radtest_node_send:
		rt_send(stmt);
		break;
		
	case radtest_node_expect:
		rt_expect(stmt);
		break;
		
	case radtest_node_exit:
		rt_exit(stmt->v.expr);
		break;
		
	case radtest_node_continue:
		break_level = stmt->v.level;
		continue_loop = 1;
		break;

	case radtest_node_break:
		break_level = stmt->v.level;
		continue_loop = 0;
		break;
		
	case radtest_node_loop:
		rt_eval_loop(stmt);
		break;
		
	case radtest_node_cond:
		rt_eval_expr(stmt->v.cond.cond, &result);
		rt_eval(rt_true_p(&result) ?
			stmt->v.cond.iftrue : stmt->v.cond.iffalse);
		break;

	case radtest_node_input:
		rt_eval_input(stmt);
		break;

	case radtest_node_set:
		radtest_parse_options(stmt->v.set.argc, stmt->v.set.argv);
		break;

	case radtest_node_shift:
	{
		int level;

		if (!stmt->v.expr)
			level = 1;
		else {
			rt_eval_expr(stmt->v.expr, &result);
			if (result.type != rtv_integer)
				runtime_error(&stmt->locus,
					      _("invalid data type in `shift'"));
			level = result.datum.number;
		}
		if (level == 0)
			break;
		if (radtest_env_shift(curenv, level))
			runtime_error(&stmt->locus,
				      _("not enough arguments to shift"));
		break;
	}

	case radtest_node_case:
		rt_eval_case(stmt);
		break;

	case radtest_node_call:
		rt_eval_call(stmt, NULL);
		break;

	case radtest_node_return:
		rt_eval_expr(stmt->v.expr, &function_result);
		break_level = 1;
		break;
		
	default:
		grad_insist_fail("Unexpected instruction code");
	}
}

static void
rt_eval_stmt_list(grad_list_t *list)
{
	grad_iterator_t *itr = grad_iterator_create(list);
	radtest_node_t *node;
	for (node = grad_iterator_first(itr);
	     node;
	     node = grad_iterator_next(itr))
		rt_eval(node);
}


/* Memory management */

struct memory_chunk {
	void *ptr;
	void (*destructor)(void *);
};
static grad_list_t /* of struct memory_chunk */ *memory_pool;


static void
register_chunk(void *ptr, void (*destructor)(void *))
{
	struct memory_chunk *p = grad_emalloc(sizeof(*p));
	if (!memory_pool)
		memory_pool = grad_list_create();
	p->ptr = ptr;
	p->destructor = destructor;
	grad_list_append(memory_pool, p);
}

static int
free_mem(void *item, void *data)
{
	struct memory_chunk *p = item;
	if (p->destructor)
		p->destructor(p->ptr);
	grad_free(p);
	return 0;
}

void
radtest_free_mem()
{
	grad_list_destroy(&memory_pool, free_mem, NULL);
	radtest_free_strings();
}

void
radtest_fix_mem()
{
	memory_pool = NULL;
	radtest_fix_strings();
}


radtest_node_t *
radtest_node_alloc(radtest_node_type type)
{
	radtest_node_t *node = grad_emalloc(sizeof(*node));
	node->type = type;
	node->locus = source_locus;
	register_chunk(node, grad_free);
	return node;
}

static void
_free_var(void *item)
{
	radtest_variable_t *var = item;
	switch (var->type) {
	case rtv_avl:
		grad_avl_free(var->datum.avl);
		break;

	case rtv_pairlist:
		grad_list_destroy(&var->datum.list, NULL, NULL);
		break;

	default:
		break;
	}
	grad_free(var);
}

radtest_variable_t *
radtest_var_alloc(radtest_data_type type)
{
	radtest_variable_t *var;
	var = grad_emalloc(sizeof(*var));
	var->type = type;
	register_chunk(var, _free_var);
	return var;
}

void
radtest_var_copy (radtest_variable_t *dst, radtest_variable_t *src)
{
	dst->type = src->type;
	dst->datum = src->datum; 
}

radtest_variable_t *
radtest_var_dup(radtest_variable_t *src)
{
	radtest_variable_t *dst = radtest_var_alloc(src->type);
	radtest_var_copy(dst, src);
	return dst;
}

radtest_case_branch_t *
radtest_branch_alloc()
{
	radtest_case_branch_t *p = grad_emalloc(sizeof(*p));
	register_chunk(p, grad_free);
	return p;
}

radtest_pair_t *
radtest_pair_alloc()
{
	radtest_pair_t *p = grad_emalloc(sizeof(*p));
	register_chunk(p, grad_free);
	return p;
}

