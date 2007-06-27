%{
/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2006,
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
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
         
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include <common.h>
#include <radtest.h>

#define YYERROR_VERBOSE 1
	
extern int yylex();

/* Local variables */ 
static int current_nesting_level; /* Nesting level of WHILE/DO statements */
static int error_count;           /* In interactive mode: number of errors
				     in the statement being compiled. Gets
				     reset to 0 after each statement.
				     In batch mode: total number of errors
				     encountered so far */
 
static struct {                   /* Definition of the function currently
				     being compiled */
	char *function;           /* Function name */
	grad_locus_t locus;       /* Location of the beginning of
				     the definition */
} defn;

/* Context stack support. This is used for improving diagnostic
   messages and after-error synchronization */
   
struct context_stack {
	struct context_stack *next;
	enum context ctx;
};

static struct context_stack *context_stack;
 
static enum context 
push_ctx(enum context ctx)
{
	struct context_stack *p = grad_emalloc(sizeof(*p));
	p->ctx = ctx;
	p->next = context_stack;
	context_stack = p;
	return ctx;
}

enum context
pop_ctx()
{
	enum context ctx;
	struct context_stack *p = context_stack;
	
	if (!context_stack)
		return ctx_none;
	ctx = p->ctx;
	context_stack = p->next;
	grad_free(p);
	return ctx;
}

enum context
peek_ctx()
{
	return context_stack ? context_stack->ctx : ctx_none;
}

/* Forward declarations */
static void run_statement(radtest_node_t *node);
static void errsync();
int yyerror(char *s);
 
%}

%token EOL AUTH ACCT SEND EXPECT T_BEGIN T_END
%token IF ELSE WHILE DO BREAK CONTINUE INPUT SHIFT GETOPT CASE IN
%token T_RETURN
%token <set> SET
%token PRINT 
%token EXIT
%token T_BOGUS
%token ARGCOUNT
%token <deref> IDENT
%token <parm> PARM
%token <string> NAME
%token <number> NUMBER
%token <string> QUOTE
%token <bstring> BSTRING
%token <ipaddr> IPADDRESS

%left PRITEM
%left OR
%left AND
%nonassoc EQ NE 
%nonassoc LT LE GT GE
%left '+' '-'
%left '*' '/' '%'
%left UMINUS NOT
%nonassoc '[' 

%type <op> op
%type <pair> pair
%type <list> pair_list maybe_pair_list prlist maybe_prlist list caselist
%type <i> closure req_code nesting_level port_type
%type <node> stmt lstmt expr maybe_expr value bool cond expr_or_pair_list
             pritem 
%type <var> send_flag imm_value
%type <symtab> send_flags send_flag_list
%type <string> name string
%type <case_branch> casecond
%type <fun> function_def

%union {
	int i;
	long number;
	char *string;
	radtest_node_t *node;
	radtest_node_deref_var_t deref;
	radtest_node_deref_parm_t parm;
	grad_uint32_t ipaddr;
	enum grad_operator op;
	radtest_pair_t *pair;
	grad_list_t *list;
	radtest_variable_t *var;
	grad_symtab_t *symtab;
	struct {
		int argc;
		char **argv;
	} set;
	radtest_case_branch_t *case_branch;
	radtest_function_t *fun;
	radtest_bstring_t bstring;
}

%%

program       : /* empty */
              | input
              | input stmt
              ; 

input         : lstmt
                {
			run_statement($1);
		}
              | input lstmt
                {
			run_statement($2);
		}
              ;

list          : lstmt
                {
			$$ = grad_list_create();
			if ($1)
				grad_list_append($$, $1);
		}
              | list lstmt
                {
			if ($2) 
				grad_list_append($1, $2);
			$$ = $1;
		}
              ;

lstmt         : /* empty */ EOL
                {
			$$ = NULL;
		}
              | stmt EOL
                {
			switch (peek_ctx()) {
			case ctx_iferr:
			case ctx_doerr:
				pop_ctx();
				break;
			default:
				break;
			}
		}
              | error EOL
                {
			errsync();
                        yyclearin;
                        yyerrok;
                }
	      ;

maybe_eol     :
              | EOL
              ;

stmt          : T_BEGIN list T_END
                {
			$$ = radtest_node_alloc(radtest_node_stmt);
			$$->v.list = $2;			
		}
              | if cond maybe_eol stmt 
                {
			pop_ctx();
			$$ = radtest_node_alloc(radtest_node_cond);
			$$->v.cond.cond = $2;
			$$->v.cond.iftrue = $4;
			$$->v.cond.iffalse = NULL;
		}
              | if cond maybe_eol stmt else stmt 
                {
			pop_ctx();
			$$ = radtest_node_alloc(radtest_node_cond);
			$$->v.cond.cond = $2;
			$$->v.cond.iftrue = $4;
			$$->v.cond.iffalse = $6;
		}
              | case expr in caselist T_END
                {
			pop_ctx();
			$$ = radtest_node_alloc(radtest_node_case);
			$$->locus = $2->locus;
			$$->v.branch.expr = $2;
			$$->v.branch.branchlist = $4;
		}
              | while { current_nesting_level++; } cond EOL stmt
                {
			pop_ctx();
			current_nesting_level--;
			$$ = radtest_node_alloc(radtest_node_loop);
			$$->v.loop.cond = $3;
			$$->v.loop.body = $5;
			$$->v.loop.first_pass = 0;
		}
              | do EOL { current_nesting_level++; } stmt EOL WHILE { current_nesting_level--; } cond  
                {
			pop_ctx();
			$$ = radtest_node_alloc(radtest_node_loop);
			$$->v.loop.cond = $8;
			$$->v.loop.body = $4;
			$$->v.loop.first_pass = 1;
		} 
              | PRINT prlist 
                {
			$$ = radtest_node_alloc(radtest_node_print);
			$$->v.list = $2;
		}
              | NAME EQ expr 
                {
			$$ = radtest_node_alloc(radtest_node_asgn);
			$$->v.asgn.name = $1;
			$$->v.asgn.expr = $3;
		}
              | SEND send_flags port_type req_code expr_or_pair_list 
                {
			$$ = radtest_node_alloc(radtest_node_send);
			$$->v.send.cntl = $2;
			$$->v.send.port_type = $3;
			$$->v.send.code = $4;
			$$->v.send.expr = $5;
		}			
              | EXPECT req_code expr_or_pair_list 
                {
			$$ = radtest_node_alloc(radtest_node_expect);
			$$->v.expect.code = $2;
			$$->v.expect.expr = $3;
		}
              | EXIT maybe_expr 
                {
			$$ = radtest_node_alloc(radtest_node_exit);
			$$->v.expr = $2;
		}
	      | BREAK nesting_level 
                {
			if ($2 > current_nesting_level) {
				parse_error(_("not enough 'while's to break from"));
			}
			$$ = radtest_node_alloc(radtest_node_break);
			$$->v.level = $2;
		}
	      | CONTINUE nesting_level 
                {
			if ($2 > current_nesting_level) {
				parse_error(_("not enough 'while's to continue"));
			}
			$$ = radtest_node_alloc(radtest_node_continue);
			$$->v.level = $2;
		}
              | INPUT
                {
			$$ = radtest_node_alloc(radtest_node_input);
			$$->v.input.expr = NULL;
			$$->v.input.var = (radtest_variable_t*)
				grad_sym_lookup_or_install(vartab,
							   "INPUT",
							   1);
		}
              | INPUT expr NAME
                {
			$$ = radtest_node_alloc(radtest_node_input);
			$$->v.input.expr = $2;
			$$->v.input.var = (radtest_variable_t*)
				grad_sym_lookup_or_install(vartab,
							   $3,
							   1);
		}
              | SET
                {
			$$ = radtest_node_alloc(radtest_node_set);
			$$->v.set.argc = $1.argc;
			$$->v.set.argv = $1.argv;
		}
              | SHIFT maybe_expr
                {
			$$ = radtest_node_alloc(radtest_node_shift);
			$$->v.expr = $2;
		}
              | function_def list T_END
                {
			$1->body = $2;
			radtest_fix_mem();
			$$ = NULL;
			defn.function = NULL;
		}
              | T_RETURN maybe_expr
                {
			if (!defn.function) {
				parse_error(_("return outside of a function definition"));
			}
			$$ = radtest_node_alloc(radtest_node_return);
			$$->v.expr = $2;
		}
              | NAME '(' maybe_prlist ')'
                {
			radtest_function_t *fun;
			
			fun = (radtest_function_t*)
				grad_sym_lookup(functab, $1);
			if (!fun) {
				parse_error(_("undefined function `%s'"), $1);
			}
			$$ = radtest_node_alloc(radtest_node_call);
			$$->v.call.fun = fun;
			$$->v.call.args = $3;
		}
              ;

function_def  : NAME EOL T_BEGIN EOL
                {
			radtest_function_t *fun;
			
			if (defn.function) {
				parse_error(_("nested function definitions "
					      "are not allowed"));
				parse_error_loc(&defn.locus,
						_("the current function "
						  "definition begins here"));
				YYERROR; /* FIXME */
			}
			defn.function = $1;
			defn.locus = source_locus;
			fun = (radtest_function_t*)
				grad_sym_lookup_or_install(functab, $1, 1);
			if (fun->body) {
				parse_error(_("redefinition of function `%s'"), $1);
				parse_error_loc(&fun->locus,
					     _("`%s' previously defined here"),
						$1);

				YYERROR; /* FIXME */
			}
			fun->locus = source_locus;
			$$ = fun;
		}
              ;

if            : IF
                {
			push_ctx(ctx_if);
		}
              ;

case          : CASE
                {
			push_ctx(ctx_case);
		}
              ;

do            : DO
                {
			push_ctx(ctx_do);
		}
              ;

while         : WHILE
                {
			push_ctx(ctx_while);
		}
              ;  

else          : ELSE maybe_eol
                {
			pop_ctx();
		}
              ;

in            : IN maybe_eol
              ;

caselist      : casecond
                {
			$$ = grad_list_create();
			grad_list_append($$, $1);
		}
              | caselist casecond
                {
			grad_list_append($1, $2);
			$$ = $1;
		}
              ;

casecond      : expr ')' stmt nls
                {
			radtest_case_branch_t *p = radtest_branch_alloc();
			p->cond = $1;
			p->node = $3;
			$$ = p;
		}
              ;

nls           : EOL
              | nls EOL
              ;

name          : /* empty */
                {
			$$ = NULL;
		}
              | NAME
	      ;

string        : NAME
              | QUOTE
              | BSTRING
                {
			parse_error(_("warning: truncating binary string"));
			$$ = $1.ptr;
		}
              ;

nesting_level : /* empty */
                {
			$$ = 1;
		}
              | NUMBER
                {
			$$ = $1;
		}
              ;

port_type     : AUTH
                {
			$$ = GRAD_PORT_AUTH;
		}
              | ACCT
                {
			$$ = GRAD_PORT_ACCT;
		}
              ;

req_code      : NUMBER
                {
			$$ = $1;
		}
              | NAME
                {
			$$ = grad_request_name_to_code($1);
			if ($$ == 0) 
				parse_error(_("expected integer value or request code name"));
		}
              ;

send_flags    : /* empty */
                {
			$$ = NULL;
		}
              | send_flag_list
              ;

send_flag_list: send_flag
                {
			radtest_variable_t *var;
			
			$$ = grad_symtab_create(sizeof(*var), var_free);
			var = (radtest_variable_t*) grad_sym_install($$,
								     $1->name);
			radtest_var_copy (var, $1);
		}
              | send_flag_list send_flag
                {
			radtest_variable_t *var;
			var = (radtest_variable_t*) grad_sym_install($1,
								     $2->name);
			radtest_var_copy (var, $2); /* FIXME: check this */
		}
              ;

send_flag     : NAME EQ NUMBER
                {
			$$ = radtest_var_alloc(rtv_integer);
			$$->name = $1;
			$$->datum.number = $3;
		}
              ;

expr_or_pair_list: /* empty */
                {
			$$ = NULL;
		}
              | pair_list
                {
			radtest_variable_t *var = radtest_var_alloc(rtv_pairlist);
			var->datum.list = $1;
			$$ = radtest_node_alloc(radtest_node_value);
			$$->v.var = var;
		}
	      | expr
	      ;
     
cond          : bool
              | NOT cond
                {
			$$ = radtest_node_alloc(radtest_node_unary);
			$$->v.unary.op = radtest_op_not;
			$$->v.unary.operand = $2;
		}
              | '(' cond ')'
                {
			$$ = $2;
		}
              | cond AND cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_and;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond OR cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_or;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond EQ cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_eq;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond LT cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_lt;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond GT	cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_gt;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond NE	cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_ne;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond LE	cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_le;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | cond GE	cond
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_ge;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              ;

bool          : expr
              ;

expr          : value
              | GETOPT string name name
                {
			char *name = $3 ? $3 : "OPTVAR";
			$$ = radtest_node_alloc(radtest_node_getopt);
			$$->v.gopt.last = 0;
			$$->v.gopt.optstr = $2;
			$$->v.gopt.var = (radtest_variable_t*)
				grad_sym_lookup_or_install(vartab, name, 1);

			name = $4 ? $4 : "OPTARG";
			$$->v.gopt.arg = (radtest_variable_t*)
				grad_sym_lookup_or_install(vartab, name, 1);

			name = $4 ? $4 : "OPTIND";
			$$->v.gopt.ind = (radtest_variable_t*)
				grad_sym_lookup_or_install(vartab, name, 1);
			
		}
              | '(' expr ')'
                {
			$$ = $2;
		}
              | expr '[' NAME closure ']' 
                {
			grad_dict_attr_t *dict = grad_attr_name_to_dict($3);
			if (!dict) {
				parse_error(_("unknown attribute `%s'"), $3);
				$$ = NULL;
			} else {
				$$ = radtest_node_alloc(radtest_node_attr);
				$$->v.attr.node = $1;
				$$->v.attr.dict = dict;
				$$->v.attr.all = $4;
				if ($4 && dict->type != GRAD_TYPE_STRING) 
					parse_error(
		     _("warning: '*' is meaningless for this attribute type"));
			}
		}
              | expr '+' expr
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_add;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | expr '-' expr
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_sub;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | expr '*' expr
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_mul;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | expr '/' expr
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_div;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | expr '%' expr
                {
			$$ = radtest_node_alloc(radtest_node_bin);
			$$->v.bin.op = radtest_op_mod;
			$$->v.bin.left = $1;
			$$->v.bin.right = $3;
		}
              | '-' expr %prec UMINUS
                {
			$$ = radtest_node_alloc(radtest_node_unary);
			$$->v.unary.op = radtest_op_neg;
			$$->v.unary.operand = $2;
		}
              | '+' expr %prec UMINUS
                {
			$$ = $2;
		}
              ;

maybe_expr    : /* empty */
                {
			$$ = NULL;
		}
              | expr
              ;

value         : imm_value
                {
			$$ = radtest_node_alloc(radtest_node_value);
			$$->v.var = $1;
		}
              | IDENT
                {
			$$ = radtest_node_alloc(radtest_node_deref);
			$$->v.deref = $1;
		}
              | PARM
                {
			$$ = radtest_node_alloc(radtest_node_parm);
			$$->v.parm = $1;
		}
              | ARGCOUNT
                {
			$$ = radtest_node_alloc(radtest_node_argcount);
		}
              | NAME '(' maybe_prlist ')'
                {
			radtest_function_t *fun;
			
			fun = (radtest_function_t*)
				grad_sym_lookup(functab, $1);
			if (!fun) {
				parse_error(_("undefined function `%s'"), $1);
				$$ = NULL;
			} else {
				$$ = radtest_node_alloc(radtest_node_call);
				$$->v.call.fun = fun;
				$$->v.call.args = $3;
			}
		}
              ;

closure       : /* empty */
                {
			$$ = 0;
		}
              | '*'
                {
			$$ = 1;
		}
              ;

imm_value     : NUMBER
                {
			$$ = radtest_var_alloc(rtv_integer);
			$$->datum.number = $1;
		}
              | IPADDRESS
                {
			$$ = radtest_var_alloc(rtv_ipaddress);
			$$->datum.ipaddr = $1;
		}
              | QUOTE
                {
			$$ = radtest_var_alloc(rtv_string);
			$$->datum.string = $1;
		}
              | BSTRING
                {
			$$ = radtest_var_alloc(rtv_bstring);
			$$->datum.bstring = $1;
		}
              | NAME 
                {
			$$ = radtest_var_alloc(rtv_string);
			$$->datum.string = $1;
		}
              | '(' maybe_pair_list ')'
                {
			$$ = radtest_var_alloc(rtv_pairlist);
			$$->datum.list = $2;
		}
              ;

maybe_prlist  : /* empty */
	        {
			$$ = NULL;
		}
              | prlist 
              ;

maybe_pair_list: /* empty */
                {
			$$ = NULL;
		}
	      | pair_list
	      ;

pair_list     : pair
                {
			$$ = grad_list_create();
			grad_list_append($$, $1);
		}
              | pair_list pair
                {
			grad_list_append($1, $2);
			$$ = $1;
		}
              | pair_list ',' pair
                {
			grad_list_append($1, $3);
			$$ = $1;
		}
              | pair_list error
              ;

pair          : NAME op expr
                {
			grad_dict_attr_t *attr = grad_attr_name_to_dict($1);
			if (!attr) 
				parse_error(_("unknown attribute `%s'"), $1);

			$$ = radtest_pair_alloc();
			$$->attr = attr;
			$$->op = $2;
			$$->node = $3;
		}
              ;

op            : EQ
                {
                        $$ = grad_operator_equal;
                } 
              | LT
                {
                        $$ = grad_operator_less_than;
                }
              | GT
                { 
                        $$ = grad_operator_greater_than;
                }
              | NE
                {
                        $$ = grad_operator_not_equal;
                }
              | LE
                {
                        $$ = grad_operator_less_equal;
                }
              | GE
                {
                        $$ = grad_operator_greater_equal;
                }
              ;

prlist        : pritem
                {
			$$ = grad_list_create();
			grad_list_append($$, $1);
		}
              | prlist ',' pritem
                {
			grad_list_append($1, $3);
			$$ = $1;
		}
              | prlist pritem
                {
			grad_list_append($1, $2);
			$$ = $1;
		}
              ;

pritem        : expr %prec PRITEM 
              ;

%%

int
yyerror(char *s)
{
	if (strcmp(s, "parse error") == 0
	    || strcmp(s, "syntax error") == 0) {
		if (yychar == T_END)
			parse_error(_("Misplaced `end'"));
		else if (yychar == EOL) {
			grad_locus_t loc = source_locus;
			loc.line--;
			parse_error_loc(&loc, _("Unexpected end of line"));
		} else if (peek_ctx() == ctx_doerr)
			;
		else 
			parse_error(s);
	} else if (yychar == EOL) {
		grad_locus_t loc = source_locus;
		loc.line--;
		parse_error_loc(&loc, s);
	} else
		parse_error(s);
}

static char *funcname_displayed = NULL;

static int
namecmp(char *a, char *b)
{
	if (!a || !b)
		return a != b;
	return strcmp(a, b);
}

static void
print_function_name()
{
	if (namecmp(funcname_displayed, defn.function)) {
		if (defn.function)
			fprintf(stderr, _("In function `%s':\n"),
				defn.function);
		else
			fprintf(stderr, _("At top level:\n"));
		funcname_displayed = defn.function;
	}
}	

void
parse_error(const char *fmt, ...)
{
        va_list ap;

	print_function_name();
	va_start(ap, fmt);
        fprintf(stderr, "%s:%lu: ",
		source_locus.file,
		(unsigned long) source_locus.line);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
	error_count++;
}

void
parse_error_loc(grad_locus_t *locus, const char *fmt, ...)
{
        va_list ap;

	print_function_name();
	va_start(ap, fmt);
        fprintf(stderr, "%s:%lu: ",
		locus->file, (unsigned long) locus->line);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
	error_count++;
}

void
set_yydebug()
{
        extern int yydebug;
        if (GRAD_DEBUG_LEVEL(1)) {
                yydebug = 1;
        }
}

static void
run_statement(radtest_node_t *node)
{
	if (!dry_run) {
		if (!error_count)
			radtest_eval(node, toplevel_env);
		/* Clear error_count only if we are in interactive
		   mode. There is no use continuing executing of a script
		   after an erroneous statement. */
		if (interactive)
			error_count = 0;
	}
	radtest_free_mem();
}

int
read_and_eval(char *filename)
{
        if (open_input(filename))
                return 1;
        return (yyparse() || error_count) ? 1 : 0;
}

static void
errsync()
{
	enum context ctx = pop_ctx();
	switch (ctx) {
	case ctx_none:
		break;
		
	case ctx_if:
		push_ctx(ctx_iferr);
		break;
		
	case ctx_do:
		current_nesting_level--;
		push_ctx(ctx_doerr);
		break;

	case ctx_while:
		current_nesting_level--;
		break;
		
	case ctx_case:
		;
	}
}
