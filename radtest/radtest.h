/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

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

#include <radius/symtab.h>
#include <radius/list.h>

#define MAX_STRING 128


/* Runtime structures and types */

typedef enum {
        rtv_undefined,           
        rtv_integer,
        rtv_ipaddress,
        rtv_string,
        rtv_pairlist,
	rtv_avl
} radtest_data_type;

typedef struct radtest_node radtest_node_t;
typedef struct radtest_variable radtest_variable_t;
typedef union radtest_datum radtest_datum_t;
typedef struct radtest_pair radtest_pair_t;
typedef struct radtest_node_send radtest_node_send_t;
typedef struct radtest_node_expect radtest_node_expect_t;
typedef struct radtest_node_deref_var radtest_node_deref_var_t;
typedef struct radtest_node_deref_parm radtest_node_deref_parm_t;
typedef struct radtest_node_attr radtest_node_attr_t;
typedef struct radtest_node_bin radtest_node_bin_t;
typedef struct radtest_node_unary radtest_node_unary_t;
typedef struct radtest_node_asgn radtest_node_asgn_t;
typedef struct radtest_node_loop radtest_node_loop_t;
typedef struct radtest_node_cond radtest_node_cond_t;
typedef struct radtest_node_input radtest_node_input_t;

struct radtest_pair {
	grad_dict_attr_t *attr;
	enum grad_operator op;
	radtest_node_t *node;
};

union radtest_datum {
	long number;
	char *string;
	grad_list_t *list;
	grad_uint32_t ipaddr;
	grad_avp_t *avl;
};

struct radtest_variable {
        grad_symbol_t *next;
        char *name;
        radtest_data_type type;
	radtest_datum_t datum;
};

typedef enum {
	radtest_node_value,
	radtest_node_bin,
	radtest_node_unary,
	radtest_node_stmt,
	radtest_node_print,
	radtest_node_asgn,
	radtest_node_send,
	radtest_node_deref,
	radtest_node_parm,
	radtest_node_expect,
	radtest_node_exit,
	radtest_node_attr,
	radtest_node_continue,
	radtest_node_break,
	radtest_node_loop,
	radtest_node_cond,
	radtest_node_input
} radtest_node_type;

struct radtest_node_send {
	grad_symtab_t *cntl;
	int port_type;
	int code;
	radtest_node_t *expr;
};

struct radtest_node_expect {
	int code;
	radtest_node_t *expr;
};

struct radtest_node_deref_var {
	char *name;
	char *repl;
};

struct radtest_node_deref_parm {
	int number;
	char *repl;
};

struct radtest_node_attr {
	radtest_node_t *node;
	grad_dict_attr_t *dict;
	int all;
};

typedef enum {
	radtest_op_add,
	radtest_op_sub,
	radtest_op_mul,
	radtest_op_div,
	radtest_op_mod,
	radtest_op_and,
	radtest_op_or,
	radtest_op_eq,
	radtest_op_ne,
	radtest_op_lt,
	radtest_op_le,
	radtest_op_gt,
	radtest_op_ge
} radtest_binop_t;

typedef enum {
	radtest_op_neg,
	radtest_op_not
} radtest_unop_t;

struct radtest_node_bin {
	radtest_binop_t op;
	radtest_node_t *left;
	radtest_node_t *right;
};

struct radtest_node_unary {
	radtest_unop_t op;
	radtest_node_t *operand;
};

struct radtest_node_asgn {
	char *name;
	radtest_node_t *expr;
};

struct radtest_node_loop {
	radtest_node_t *cond;
	radtest_node_t *body;
	int first_pass;
};

struct radtest_node_cond {
	radtest_node_t *cond;
	radtest_node_t *iftrue;
	radtest_node_t *iffalse;
};

struct radtest_node_input {
	radtest_node_t *expr;
	char *name;
};

struct radtest_node {
	radtest_node_t *next;
	grad_locus_t locus;
	radtest_node_type type;
	union {
		radtest_node_t *expr;         /* exit */
		radtest_node_bin_t bin;
		radtest_node_unary_t unary;
		grad_list_t *list;            /* print/stmt */
		radtest_node_send_t send;     /* radtest_node_send */
		radtest_node_expect_t expect; /* radtest_node_expect */
		radtest_variable_t *var;      /* radtest_node_exit,
					         radtest_node_asgn,
					         radtest_node_value */
		radtest_node_deref_parm_t parm;
		radtest_node_deref_var_t deref;
		radtest_node_attr_t attr;
		int level;                    /* break/continue */
		radtest_node_asgn_t asgn;
		radtest_node_loop_t loop;
		radtest_node_cond_t cond;
		radtest_node_input_t input;
	} v;
};


/* External declarations */
extern grad_locus_t source_locus;
extern grad_symtab_t *vartab;
extern grad_uint32_t auth_server;
extern int   auth_port;
extern grad_uint32_t acct_server;
extern int   acct_port;
extern u_char messg_id;
extern int reply_code;
extern grad_avp_t *reply_list;
extern int verbose;
extern int abort_on_failure;
extern int x_argmax;
extern int x_argc;
extern char **x_argv;
extern int disable_readline;
extern int dry_run;

int open_input(char *name);
void close_input();
void set_yydebug();
void parse_error(const char *fmt, ...);
void print(radtest_variable_t *var);
void radtest_send(int port, int code, grad_avp_t *avl, grad_symtab_t *cntl);
void putback(char *str);
void prompt();
void tempvar_free(radtest_variable_t *var);
int var_free(radtest_variable_t *var);
void var_print(radtest_variable_t *var);
int compare_lists(grad_avp_t *reply, grad_avp_t *sample);
radtest_data_type parse_datum(char *p, radtest_datum_t *dp);


/* Memory management */
radtest_node_t *radtest_node_alloc(radtest_node_type);
radtest_pair_t *radtest_pair_alloc();
radtest_variable_t *radtest_var_alloc(radtest_data_type);
void radtest_var_copy (radtest_variable_t *dst, radtest_variable_t *src);
void radtest_free_variables();
void radtest_free_nodes();
radtest_pair_t *radtest_pair_alloc();
void radtest_free_pairs();
void radtest_free_strings();

void radtest_start_string(char *str);
void radtest_add_string(char *str);
char *radtest_end_string();


/* Readline completion */
char **radtest_command_completion(char *text, int start, int end);


