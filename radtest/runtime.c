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

static jmp_buf errbuf;
static int break_level;
static int continue_loop;

static void rt_eval_stmt_list(grad_list_t *list);
static void rt_eval_expr(radtest_node_t *node, radtest_variable_t *result);
static void rt_eval(radtest_node_t *stmt);

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

/* Main entry point */

int
radtest_eval(radtest_node_t *stmt)
{
	if (setjmp(errbuf))
		return 1;
	break_level = continue_loop = 0;
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
                   runtime_error(locus, _("Division by zero")); \
          	result->datum.number = a / b;       \
		break;                              \
		                                    \
	case radtest_op_mod:                        \
                if (b == 0)                         \
                   runtime_error(locus, _("Division by zero")); \
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

static void
bin_type_error(grad_locus_t *locus)
{
	runtime_error(locus, _("Invalid data type in binary operation"));
}

static void
unary_type_error(grad_locus_t *locus)
{
	runtime_error(locus, _("Invalid data type in unary operation"));
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
		bin_type_error(locus);
	}
}

static char *
cast_to_string(grad_locus_t *locus, radtest_variable_t *var)
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
		runtime_error(locus, _("Data type cannot be cast to string"));
	}
	return buf;
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
	if (!var)
		result->type = rtv_undefined;
	else
		radtest_var_copy(result, var);
	p = node->v.deref.repl;
	if (p) switch (*p++) {
        case '=':
		if (!var)
			var = (radtest_variable_t*) grad_sym_install(vartab,
								     node->v.deref.name);
                var->type = parse_datum(p, &var->datum);
		radtest_var_copy(result, var);
                break;
                
        case '-':
                switch (result->type = parse_datum(p, &datum)) {
                case rtv_undefined:
                        runtime_error(&node->locus,
				      _("variable %s used before definition"),
				      node->v.deref.name);
                        break;
                        
                case rtv_integer:
                case rtv_ipaddress:
		case rtv_string:
			result->datum = datum;
			break;

		default:
			runtime_error(&node->locus,
				      _("%s:%d: Unknown data type"),
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
			      _("Variable %s used before definition"),
			      node->v.deref.name);
}

static void
rt_eval_parm(radtest_node_t *node, radtest_variable_t *result)
{
	int num = node->v.parm.number;
	char *p;
	size_t n;
	
	result->type = rtv_string;
        if (num < x_argc && x_argv[num]) {
		radtest_start_string(x_argv[num]);
		result->datum.string = radtest_end_string();
                return;
        }
        
        if (!node->v.parm.repl) {
		radtest_start_string("");
		result->datum.string = radtest_end_string();
                return;
        }
        p = node->v.parm.repl;
	
        switch (*p++) {
        case '=':
                if (num > x_argmax) {
                        x_argmax = num;
                        x_argv = grad_erealloc(x_argv, sizeof(x_argv[0])*(num+1));
                }
                x_argv[num] = grad_estrdup(p);
                x_argc = num+1;
		radtest_start_string(x_argv[num]);
		result->datum.string = radtest_end_string();
                break;
                
        case '-':
		radtest_start_string(p);
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
		radtest_start_string(x_argv[num]);
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
			grad_insist_fail("invalid data type in rt_eval_pairlist");
			
		case rtv_pairlist:
		case rtv_avl:
			runtime_error(locus, _("Invalid data type"));
			break;
			
		case rtv_integer:
			switch (p->attr->type) {
			case TYPE_STRING:
			case TYPE_DATE:
				snprintf(buf, sizeof buf, "%ld",
					 val.datum.number);
				pair = grad_avp_create_string(p->attr->value,
							      buf);
				break;
				
			case TYPE_INTEGER:
			case TYPE_IPADDR:
				pair = grad_avp_create_integer(p->attr->value,
							       val.datum.number);
				break;
			}
			break;
			
		case rtv_ipaddress:
			switch (p->attr->type) {
			case TYPE_STRING:
			case TYPE_DATE:
				snprintf(buf, sizeof buf, "%lu",
					 val.datum.ipaddr);
				pair = grad_avp_create_string(p->attr->value,
							      buf);
				break;
				
			case TYPE_INTEGER:
			case TYPE_IPADDR:
				pair = grad_avp_create_integer(p->attr->value,
							       val.datum.ipaddr);
				break;
			}
			break;

		case rtv_string:
			switch (p->attr->type) {
			case TYPE_STRING:
			case TYPE_DATE:
				pair = grad_avp_create_string(p->attr->value,
							      val.datum.string);
				break;
				
			case TYPE_INTEGER:
			{
				grad_dict_value_t *dv = grad_value_name_to_value(val.datum.string, p->attr->value);
				if (dv) {
					pair = grad_avp_create_integer(p->attr->value,
								       dv->value);
					break;
				}
			}
			/*FALLTHROUGH*/
					
			case TYPE_IPADDR:
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

	default:
		*result = *var;
	}
}

static void
rt_eval_expr(radtest_node_t *node, radtest_variable_t *result)
{
	radtest_variable_t left, right;
	
	switch (node->type) {
	case radtest_node_value:
		rt_eval_variable(&node->locus, result, node->v.var);
		break;
		
	case radtest_node_bin:
		rt_eval_expr(node->v.bin.left, &left);
		rt_eval_expr(node->v.bin.right, &right);
		
		switch (left.type) {
		case rtv_integer:
			switch (right.type) {
			case rtv_integer:
				rt_eval_bin_int(&node->locus,
						result,
						node->v.bin.op,
						left.datum.number,
						right.datum.number);
				break;
				
			case rtv_ipaddress:
			{
				grad_uint32_t v = left.datum.number;
				rt_eval_bin_uint(&node->locus,
						 result,
						 node->v.bin.op,
						 v,
						 right.datum.ipaddr);
				break;
			}
			
			case rtv_string:
			{
				long v;

				if (isdigit(right.datum.string[0])) {
					char *p;
					p = strtol(right.datum.string, &p, 0);
					if (*p)
						runtime_error(&node->locus,
				      _("cannot convert string to integer: %s"),
							      right.datum.string);
				} else if ((v = grad_request_name_to_code(right.datum.string)) == 0)
					runtime_error(&node->locus,
				 _("cannot convert string to integer: %s"),
							 right.datum.string);
					   
				    
				rt_eval_bin_int(&node->locus,
						result,
						node->v.bin.op,
						left.datum.number,
						v);
				break;
			}
			
			case rtv_avl:
				bin_type_error(&node->locus);
				break;
				
			case rtv_pairlist:
				grad_insist_fail("a value cannot evaluate to rtv_pairlist");
			}
			break;
				
		case rtv_ipaddress:
			switch (right.type) {
			case rtv_integer:
				rt_eval_bin_int(&node->locus,
						result,
						node->v.bin.op,
						left.datum.number,
						right.datum.number);
				break;
				
			case rtv_ipaddress:
				bin_type_error(&node->locus);
				break;
				
			case rtv_string:
			{
				grad_uint32_t v = grad_ip_gethostaddr(right.datum.string);
				/* FIXME: no way to check for errors */
				rt_eval_bin_uint(&node->locus,
						 result,
						 node->v.bin.op,
						 left.datum.ipaddr,
						 v);
				break;
			}
						
			case rtv_avl:
				bin_type_error(&node->locus);
				break;
				
			case rtv_pairlist:
				grad_insist_fail("a value cannot evaluate to rtv_pairlist");
			}
			break;
			
		case rtv_string:
			rt_eval_bin_str(&node->locus,
					result,
					node->v.bin.op,
					left.datum.string,
					cast_to_string(&node->locus, &right));
			break;
				
		case rtv_pairlist:
			grad_insist_fail("a value cannot evaluate to rtv_pairlist");

		case rtv_avl:
			if (right.type != rtv_avl) 
				bin_type_error(&node->locus);
			grad_avl_merge(&right.datum.avl, &left.datum.avl);
			grad_avl_free(left.datum.avl);
			radtest_var_copy(result, &right);
			break;
		}
		break;
		
	case radtest_node_unary:
		rt_eval_expr(node->v.unary.operand, &left);
		switch (node->v.unary.op) {
		case radtest_op_neg:
			if (left.type != rtv_integer)
				unary_type_error(&node->locus);
			/* FIXME: typecast? */
			result->type = rtv_integer;
			result->datum.number = - left.datum.number;
			break;
			
		case radtest_op_not:
			if (left.type != rtv_integer)
				unary_type_error(&node->locus);
			/* FIXME: typecast? */
			result->type = rtv_integer;
			result->datum.number = ! left.datum.number;
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
			runtime_error(&node->locus, _("Not a pair list"));
		p = grad_avl_find(left.datum.avl, node->v.attr.dict->value);
		switch (node->v.attr.dict->type) {
		case TYPE_STRING:
		case TYPE_DATE:    
			result->type = rtv_string;
			result->datum.string = p ? p->avp_strvalue : "";
			break;
			
		case TYPE_INTEGER:
			result->type = rtv_integer;
			result->datum.number = p ? p->avp_lvalue : 0;
			break;
			
		case TYPE_IPADDR:
			result->type = rtv_ipaddress;
			result->datum.number = p ? p->avp_lvalue : 0;
			break;
		}
		break;
	}
	
	default:
		grad_insist_fail("Unexpected node type");
	}
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
	
	var = (radtest_variable_t*) grad_sym_lookup(vartab, node->v.asgn.name);

	if (var == NULL)
		var = (radtest_variable_t*) grad_sym_install(vartab,
							     node->v.asgn.name);
	
	var->type = result.type;
	switch (result.type) {
        case rtv_undefined:
        case rtv_integer:
        case rtv_ipaddress:
		var->datum = result.datum;
		break;
		
        case rtv_string:
		var->datum.string = grad_estrdup(result.datum.string);
		break;
		
	case rtv_avl:
		var->datum.avl = result.datum.avl;
		break;
		
        case rtv_pairlist:
		grad_insist_fail("rtv_pairlist in assignment");
		
	default:
		grad_insist_fail("invalid data type in assignment");
	}
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
				      _("Invalid data type in send statement (expected A/V list"));
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
		printf("expect %d\n", exp->code);
		printf("got    %d\n", reply_code);
	}
	if (reply_code != exp->code) {
		pass = 0;
	}
	if (exp->expr) {
		radtest_variable_t result;
		rt_eval_expr(exp->expr, &result);
		if (result.type != rtv_avl)
			runtime_error(&node->locus,
				      _("Expected A/V pair list"));
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
			runtime_error(&expr->locus,
				      _("Invalid data type in exit statement"));
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
static grad_list_t /* of radtest_node_t */ *node_pool;

radtest_node_t *
radtest_node_alloc(radtest_node_type type)
{
	radtest_node_t *node = grad_emalloc(sizeof(*node));
	node->type = type;
	node->locus = source_locus;
	if (!node_pool)
		node_pool = grad_list_create();
	grad_list_append(node_pool, node);
	return node;
}

static int
_free_item(void *item, void *data)
{
	grad_free(item);
}

void
radtest_free_nodes()
{
	grad_list_destroy(&node_pool, _free_item, NULL);
}


/* Variables */

static grad_list_t /* of radtest_variable_t */ *value_pool;
   
radtest_variable_t *
radtest_var_alloc(radtest_data_type type)
{
	radtest_variable_t *var;
	var = grad_emalloc(sizeof(*var)); 
	var->type = type;
	if (!value_pool)
		value_pool = grad_list_create();
	grad_list_append(value_pool, var);
	return var;
}

void
radtest_var_copy (radtest_variable_t *dst, radtest_variable_t *src)
{
	dst->type = src->type;
	dst->datum = src->datum; 
}

static int
_free_var(void *item, void *data)
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

void
radtest_free_variables()
{
	grad_list_destroy(&value_pool, _free_var, NULL);
}


/* Pairs */

static grad_list_t /* of radtest_pair_t */ *pair_pool;

radtest_pair_t *
radtest_pair_alloc()
{
	radtest_pair_t *p;
	p = grad_emalloc(sizeof(*p));
	if (!pair_pool)
		pair_pool = grad_list_create();
	grad_list_append(pair_pool, p);
	return p;
}

void
radtest_free_pairs()
{
	grad_list_destroy(&pair_pool, _free_item, NULL);
}


void
radtest_free_mem()
{
	radtest_free_nodes();
	radtest_free_variables();
	radtest_free_pairs();
	radtest_free_strings();
}
