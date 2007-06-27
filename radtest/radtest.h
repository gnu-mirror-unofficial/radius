/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2007 Free Software Foundation, Inc.

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

#include <radius/symtab.h>
#include <radius/list.h>


/* Data representation */

typedef struct radtest_variable radtest_variable_t;
typedef struct radtest_function radtest_function_t;
typedef union radtest_datum radtest_datum_t;
typedef struct radtest_pair radtest_pair_t;
typedef struct radtest_bstring radtest_bstring_t;

typedef enum {
        rtv_undefined,           /* Undefined variable */
        rtv_integer,             /* Signed integer value */
        rtv_ipaddress,           /* Unsigned integer value */
        rtv_string,              /* String. */
	rtv_bstring,             /* Binary string */
        rtv_pairlist,            /* Temporary representation of A/V pair
				    list. */
	rtv_avl                  /* A/V pair list */
} radtest_data_type;

#define RTV_MAX rtv_avl+1

struct radtest_bstring {
	char *ptr;
	int length;
};

union radtest_datum {
	long number;               /* rtv_integer */
	grad_uint32_t ipaddr;      /* rtv_ipaddress */ 
	char *string;              /* rtv_string */
	radtest_bstring_t bstring; /* rtv_bstring */
	grad_list_t *list;         /* rtv_pairlist */
	grad_avp_t *avl;           /* rtv_avl */
};

struct radtest_variable {
        grad_symbol_t *next;     /* Pointer to the next variable in the hash
				    bucket */
        char *name;              /* Variable name */
        radtest_data_type type;  /* Data type */
	radtest_datum_t datum;   /* Data */
};

struct radtest_function {
        grad_symbol_t *next;     /* Pointer to the next function in the hash
				    bucket */
        char *name;              /* Function name */
	grad_locus_t locus;      /* Location of the function definition */
	grad_list_t *body;       /* List of radtest_node_t (see below)
				    representing function body */
};

/* Radtest evaluator data types */

/* General-purpose tree node */
typedef struct radtest_node radtest_node_t;

/* Data access nodes */
typedef struct radtest_node_deref_var radtest_node_deref_var_t;
typedef struct radtest_node_deref_parm radtest_node_deref_parm_t;
typedef struct radtest_node_attr radtest_node_attr_t;

/* Operation nodes */ 
typedef struct radtest_node_bin radtest_node_bin_t;
typedef struct radtest_node_unary radtest_node_unary_t;

/* Assignment */
typedef struct radtest_node_asgn radtest_node_asgn_t;

/* Control flow nodes */
typedef struct radtest_node_cond radtest_node_cond_t;
typedef struct radtest_node_case radtest_node_case_t;
typedef struct radtest_case_branch radtest_case_branch_t;
typedef struct radtest_node_loop radtest_node_loop_t;
typedef struct radtest_node_call radtest_node_call_t;

/* Built-in functions */
typedef struct radtest_node_send radtest_node_send_t;
typedef struct radtest_node_expect radtest_node_expect_t;
typedef struct radtest_node_input radtest_node_input_t;
typedef struct radtest_node_set radtest_node_set_t;
typedef struct radtest_node_getopt radtest_node_getopt_t;

/* Temporary representation of an A/V pair */
struct radtest_pair {
	grad_dict_attr_t *attr;     /* Attribute */
	enum grad_operator op;      /* Comparison operator */
	radtest_node_t *node;       /* Evaluate this statement to obtain
				       actual pair value */
};

/* Node type */
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
	radtest_node_input,
	radtest_node_set,
	radtest_node_shift,
	radtest_node_getopt,
	radtest_node_case,
	radtest_node_call,
	radtest_node_return,
	radtest_node_argcount
} radtest_node_type;

/* Variable dereference */
struct radtest_node_deref_var {
	char *name;                /* Variable name */
	char *repl;                /* Replacement value if it is undefined */ 
};

struct radtest_node_deref_parm {
	int number;                /* Parameter number */
	char *repl;                /* Replacement value if it is undefined */ 
};

/* Attribute dereference */
struct radtest_node_attr {
	radtest_node_t *node;      /* Code evaluating to rtv_avl */
	grad_dict_attr_t *dict;    /* Attribute definition */ 
	int all;                   /* Concatenate all occurrences of the
				      attribute (for string attributes
				      only) */
};

typedef enum { /* Binary opcodes */
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

typedef enum {  /* Unary opcode */
	radtest_op_neg,
	radtest_op_not
} radtest_unop_t;

/* Binary operation */
struct radtest_node_bin {
        radtest_binop_t op;        /* Opcode */
	radtest_node_t *left;      /* Left subtree */
	radtest_node_t *right;     /* Right subtree */
};

/* Unary operation */
struct radtest_node_unary { 
	radtest_unop_t op;         /* Opcode */ 
	radtest_node_t *operand;   /* Operand subtree */
};

/* Assignment */
struct radtest_node_asgn {
	char *name;                /* Variable name */
	radtest_node_t *expr;      /* RHS subtree */
};

/* Conditional branching ('if' statement) */
struct radtest_node_cond {  
	radtest_node_t *cond;      /* Condition */ 
	radtest_node_t *iftrue;    /* Execute if cond evaluates to true */ 
	radtest_node_t *iffalse;   /* Execute if cond evaluates to false */
};

/* Conditional branching ('case' statement) */
struct radtest_node_case {
	radtest_node_t *expr;      /* Switch argument */  
	grad_list_t *branchlist;   /* List of conditions
				      (radtest_case_branch_t) */
};

/* A single 'case' condition */
struct radtest_case_branch {
	radtest_node_t *cond;      /* Evaluates to string (regexp text) */
	radtest_node_t *node;      /* Statement to execute if the switch arg
				      matches cond */
};

/* Loop statement */
struct radtest_node_loop {
	radtest_node_t *cond;      /* Loop condition */
	radtest_node_t *body;      /* Loop body */
	int first_pass;            /* 1 for 'do' loops */
};

/* Function call */
struct radtest_node_call {
	radtest_function_t *fun;   /* Function itself */
	grad_list_t *args;         /* List of subtrees (radtest_node_t)
				      evaluating to function parameters */
};

/* 'send' statement */
struct radtest_node_send {
	grad_symtab_t *cntl;       /* Controlling dictionary */ 
	int port_type;             /* Type of port to send the request to */
	int code;                  /* Request code */
	radtest_node_t *expr;      /* Expression evaluating to request pairs
				      (rtv_avl). */
};

/* 'expect' statement */
struct radtest_node_expect {
	int code;                  /* Request code */
	radtest_node_t *expr;      /* Request pairs (evaluates to rtv_avl) */
};

/* 'input' statement */
struct radtest_node_input {
	radtest_node_t *expr;      /* Prompt (evaluates to rtv_string) */
	radtest_variable_t *var;   /* Variable to assign to */
};

/* 'set' statement */
struct radtest_node_set {
	int argc;
	char **argv;
};

/* 'getopt' statement */
struct radtest_node_getopt {
	char *optstr;              /* Option string */
	int last;                  /* Result of the last call to getopt().
				      <=0 means initialize getopt */
	int argc;                  /* Arguments to getopt() */
	char **argv;               /* Arguments to getopt() */
	radtest_variable_t *var;   /* OPTVAR */ 
	radtest_variable_t *arg;   /* OPTARG */ 
	radtest_variable_t *ind;   /* OPTIND */
};

/* Parse tree node structure */
struct radtest_node {
	grad_locus_t locus;        /* Definition location */
	radtest_node_type type;    /* Node type */
	union {
		                                /* radtest_node_... */
		radtest_node_t *expr;           /* exit/shift/return */
		grad_list_t *list;              /* print/stmt */
		radtest_variable_t *var;        /* value */

		radtest_node_deref_parm_t parm; /* deref_parm */
		radtest_node_deref_var_t deref; /* deref */
		radtest_node_attr_t attr;       /* attr */

		radtest_node_bin_t bin;         /* binop */ 
		radtest_node_unary_t unary;     /* unop */

		radtest_node_asgn_t asgn;       /* asgn */  

		radtest_node_cond_t cond;       /* cond */
		radtest_node_case_t branch;     /* case */
		radtest_node_loop_t loop;       /* loop */
		radtest_node_call_t call;       /* call */
		int level;                      /* break/continue */

		radtest_node_send_t send;       /* send */
		radtest_node_expect_t expect;   /* radtest_node_expect */
		radtest_node_input_t input;     /* input */
		radtest_node_set_t set;         /* set */
		radtest_node_getopt_t gopt;     /* getopt */ 
	} v;
};

enum context {
	ctx_none,
	ctx_if,
	ctx_iferr,
	ctx_do,
	ctx_doerr,
	ctx_while,
	ctx_case
};


/* External declarations */
extern grad_locus_t source_locus;
extern grad_symtab_t *vartab, *functab;
extern int reply_code;
extern grad_avp_t *reply_list;
extern int verbose;
extern int disable_readline;
extern int dry_run;
extern int interactive;

extern grad_list_t *toplevel_env;

int radtest_parse_options(int argc, char **argv);
int read_and_eval(char *filename);
int open_input(char *name);
void close_input();
void set_yydebug();
void parse_error(const char *fmt, ...);
void parse_error_loc(grad_locus_t *locus, const char *fmt, ...);
void radtest_send(int port, int code, grad_avp_t *avl, grad_symtab_t *cntl);
void var_print(radtest_variable_t *var);
int compare_lists(grad_avp_t *reply, grad_avp_t *sample);
radtest_data_type parse_datum(char *p, radtest_datum_t *dp);

int radtest_eval(radtest_node_t *stmt, grad_list_t *list);


/* Memory management */
radtest_node_t *radtest_node_alloc(radtest_node_type);
radtest_pair_t *radtest_pair_alloc();
radtest_variable_t *radtest_var_alloc(radtest_data_type);
radtest_variable_t *radtest_var_dup(radtest_variable_t *src);
void radtest_var_copy (radtest_variable_t *dst, radtest_variable_t *src);
radtest_pair_t *radtest_pair_alloc();
radtest_case_branch_t *radtest_branch_alloc();
int var_free(radtest_variable_t *var);

void radtest_free_mem();
void radtest_fix_mem();

void radtest_start_string(char *str);
void radtest_add_string(char *str);
char *radtest_end_string();
void radtest_free_strings();
void radtest_fix_strings();


void radtest_env_add_string(grad_list_t *env, char *string);
void radtest_env_add(grad_list_t *env, radtest_variable_t *var);
radtest_variable_t *radtest_env_get(grad_list_t *env, int n);
int radtest_env_shift(grad_list_t *env, int amount);
void radtest_env_to_argv(grad_list_t *env, grad_locus_t *locus,
			 int *pargc, char ***pargv);


/* Readline completion */
char **radtest_command_completion(char *text, int start, int end);


