%{
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

#define RADIUS_MODULE_REWRITE_Y
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <radiusd.h>
#include <symtab.h>
#include <setjmp.h>
#include <varargs.h>
#include <obstack1.h>
#include <argcv.h>
#include <rewrite.h>
#ifdef USE_SERVER_GUILE	
# include <libguile.h>
#endif
	
#ifndef lint
static char rcsid[] =
  "@(#) $Id$";
#endif


/*
 * Generalized list structure
 */
typedef struct list_t LIST;
#define LIST(type) \
	type     *next;\
	type     *prev

struct list_t {
	LIST(LIST);
};

/*
 * Generalized object 
 */
typedef struct object_t OBJECT ;

#define OBJ(type) \
	LIST(type);\
	type    *alloc

struct object_t {
	OBJ(OBJECT);
};

typedef struct {
	size_t   size;        /* Size of an element */
	void     (*free)();   /* deallocator */ 
	OBJECT   *alloc_list; /* list of allocated elements */
} OBUCKET;

	
/* ************************************************************
 * Basic data types
 */

typedef int stkoff_t;          /* Offset on stack */
typedef unsigned int pctr_t;   /* Program counter */
typedef void (*INSTR)();        /* program instruction */

/* Compiled regular expression
 */
typedef struct comp_regex COMP_REGEX;
struct comp_regex {
	OBJ(COMP_REGEX);
	regex_t      regex;    /* compiled regex itself */
	int          nmatch;   /* number of \( ... \) groups */
};

/*
 * Binary Operations
 */
typedef enum {
	Eq,
	Ne,
	Lt,
	Le,
	Gt,
	Ge,
	BAnd,
	BXor,
	BOr,
	And,
	Or,
	Shl,
	Shr,
	Add,
	Sub,
	Mul,
	Div,
	Rem,
	Max_opcode
} Bopcode;

/*
 * Unary operations
 */
typedef enum {
	Neg,
	Not,
	Max_unary
} Uopcode;

/*
 * Matrix types
 */
typedef enum {
	Generic,
	Nop,
	Enter,
	Leave,
	Stop,
	Constant,
	Matchref,
	Variable,
	Unary,
	Binary,
	Cond,
	Asgn,
	Match,
	Coercion,
	Expression,
	Return,
	Jump,
	Branch,
	Target,
	Call,
	Builtin,
	Pop,
	Pusha,
	Popa,
	Attr,
	Attr_asgn,
	Attr_check,
	Max_mtxtype
} Mtxtype;

/*
 * Function parameter
 */
typedef struct parm_t PARAMETER;
struct parm_t {
	PARAMETER   *prev;     /* Previous parameter */
	PARAMETER   *next;     /* Next parameter */
	Datatype    datatype;  /* type */
	stkoff_t    offset;    /* Offset on stack */
};

/*
 * Local variable
 */
typedef struct variable VAR;
struct variable {
	OBJ(VAR);
	VAR       *dcllink;  /* Link to the next variable vithin the
			      * same declaration
			      */
	char      *name;     /* name of the variable */
	int       level;     /* nesting level */
	int       offset;    /* offset on stack */
	Datatype  datatype;  /* type */
	int       constant;  /* true if assigned a constant value */
	Datum     datum;     /* constant value itself */
};

/*
 * Function definition
 */
typedef struct function_def {
	struct function_def *next;
	char       *name;        /* Function name */
	Datatype   rettype;      /* Return type */
	pctr_t     entry;        /* Code entry */
	COMP_REGEX *rx_list;     /* List of compiled regexps */
	int        nparm;        /* Number of parameters */
	PARAMETER  *parm;        /* List of parameters */
	stkoff_t   stack_alloc;  /* required stack allocation */
	int        line;         /* source line where the function
				  * was declared
				  */
} FUNCTION;

#define STACK_BASE 2

/*
 * Built-in function
 */
typedef struct  {
	INSTR    handler;        /* Function itself */
	char     *name;          /* Function name */
	Datatype rettype;        /* Return type */
	char     *parms;         /* coded parameter types */
} builtin_t;

/*
 * Operation matrices
 */
typedef union mtx MTX;
/*
 * All matrices contain the following common fields:
 *    alloc- link to the previously allocated matrix.
 *           It is used at the end of code generation
 *           pass to free all allocated matrices.
 *    next - link to the next matrix in the subexpression
 *    prev - link to the previous matrix in the subexpression
 * Additionally, all expression matrices contain the field
 * `datatype' which contains the data type for this matrix.
 */
#if defined(MAINTAINER_MODE)
# define COMMON_MTX \
	OBJ(MTX);\
	int      id;\
	int      line;\
	Mtxtype  type;
#else
# define COMMON_MTX \
	OBJ(MTX);\
	int      line;\
	Mtxtype  type;
#endif
	
#define COMMON_EXPR_MTX \
	COMMON_MTX\
	Datatype datatype;\
	MTX      *uplink;\
	MTX      *arglink;

/*
 * Generic matrix: nothing special
 * Type: Generic
 */
typedef struct {
	COMMON_EXPR_MTX
} GEN_MTX;
/*
 * Constant matrix
 * Type: Constant
 */
typedef struct {
	COMMON_EXPR_MTX
	Datum    datum;     /* Constant value */      
} CONST_MTX;
/*
 * Reference to a previous regexp: corresponds to a \N construct
 * Type: Matchref
 */
typedef struct {
	COMMON_EXPR_MTX
	int      num;       /* Number of \( ... \) to be referenced */
} MATCHREF_MTX;
/*
 * Reference to a variable
 * Type: Variable
 */
typedef struct {
	COMMON_EXPR_MTX
	VAR      *var;      /* Variable being referenced */ 
} VAR_MTX;
/*
 * Unary operation matrix
 * Type: Unary
 */
typedef struct {
	COMMON_EXPR_MTX
	Uopcode  opcode;    /* Operation code */
	MTX      *arg;      /* Argument */
} UN_MTX;
/*
 * Binary operation matrix
 * Type: Binary
 */
typedef struct {
	COMMON_EXPR_MTX
	Bopcode   opcode;   /* Operation code */ 
	MTX      *arg[2];   /* Arguments */ 
} BIN_MTX;
/*
 * Assignment matrix
 * Type: Asgn
 */
typedef struct {
	COMMON_EXPR_MTX
	VAR      *lval;     /* Lvalue */
	MTX      *arg;      /* Rvalue */
} ASGN_MTX;
/*
 * Conditional expression matrix
 * Type: Cond
 */
typedef struct {
	COMMON_MTX
	MTX      *expr;     /* Conditional expression */
	MTX      *if_true;  /* Branch if true */
	MTX      *if_false; /* Branch if false */ 
} COND_MTX;
/*
 * Regexp match
 * Type: Match
 */
typedef struct {
	COMMON_EXPR_MTX
	int        negated; /* Is the match negated ? */
	MTX        *arg;    /* Argument (lhs) */
	COMP_REGEX *rx;     /* Regexp (rhs) */
} MATCH_MTX;
/*
 * Type coercion
 * Type: Coerce
 */
typedef struct {
	COMMON_EXPR_MTX
	MTX      *arg;      /* Argument of the coercion */ 
} COERCE_MTX;
/*
 * Expression
 * Type: Expression
 */
typedef struct {
	COMMON_EXPR_MTX
	MTX      *expr;
} EXPR_MTX;
/*
 * Return from function
 * Type: Return
 */
typedef struct {
	COMMON_EXPR_MTX
	MTX      *expr;     /* Return value */
} RET_MTX;
/*
 * Unconditional branch (jump)
 * Type: Jump
 */
typedef struct {
	COMMON_MTX
	MTX *link;          /* Link to the next jump matrix
			     * (for break and continue matrices)
			     */
	MTX      *dest;     /* Jump destination (usually NOP matrix) */
} JUMP_MTX;
/*
 * Conditional branch
 * Type: Branch
 */
typedef struct {
	COMMON_MTX
	int      cond;      /* Condition: 1 - equal, 0 - not equal */
	MTX      *dest;     /* Jump destination (usually NOP matrix) */
} BRANCH_MTX;
/*
 * Stack frame matrix
 * Type: Enter, Leave
 */
typedef struct {
	COMMON_MTX
	stkoff_t  stacksize;/* Required stack size */
} FRAME_MTX;
/*
 * Jump target
 * Type: Target
 */
typedef struct {
	COMMON_MTX
	pctr_t  pc;         /* Target's program counter */
} TGT_MTX;
/*
 * No-op matrix. It is always inserted at the branch destination
 * points. It's purpose is to fixup the jump statements.
 * Type: Nop
 */
typedef struct {
	COMMON_MTX
	TGT_MTX   *tgt;     /* Target list */
	pctr_t     pc;      /* Program counter for backward
			       references */
} NOP_MTX;
/*
 * Function call
 * Type: Call
 */
typedef struct {
	COMMON_EXPR_MTX
	FUNCTION  *fun;     /* Called function */
	int       nargs;    /* Number of arguments */
	MTX       *args;    /* Arguments */
} CALL_MTX;
/*
 * Builtin function call
 * Type: Builtin
 */
typedef struct {
	COMMON_EXPR_MTX
	INSTR     fun;      /* Handler function */
	int       nargs;    /* Number of arguments */   
	MTX       *args;    /* Arguments */
} BTIN_MTX;
/*
 * Attribute matrix
 * Type: Attr, Attr_asgn, Attr_check
 */
typedef struct {
	COMMON_EXPR_MTX
	int       attrno;   /* Attribute number */
	MTX       *rval;    /* Rvalue */
} ATTR_MTX;

union mtx {
	GEN_MTX    gen;
	NOP_MTX    nop;
	FRAME_MTX  frame;
	CONST_MTX  cnst;
	MATCHREF_MTX    ref;
	VAR_MTX    var;
	UN_MTX     un;
	BIN_MTX    bin;
	COND_MTX   cond;
	ASGN_MTX   asgn;
	MATCH_MTX  match;
	COERCE_MTX coerce;
	RET_MTX    ret;
	JUMP_MTX   jump;
	BRANCH_MTX branch;
	TGT_MTX    tgt;
	CALL_MTX   call;
	BTIN_MTX   btin;
	ATTR_MTX   attr;
};

/*
 * Stack frame
 */
typedef struct frame_t FRAME;

struct frame_t {
	OBJ(FRAME);
	int       level;        /* nesting level */
	stkoff_t  stack_offset; /* offset in the stack */
};

/* *****************************************************************
 * Static data
 */
/*
 * Stack Frame list
 */
static OBUCKET frame_bkt = { sizeof(FRAME), NULL };
static FRAME *frame_first, *frame_last;
#define curframe frame_last

static int errcnt;         /* Number of errors detected */ 
static FUNCTION *function; /* Function being compiled */
static Symtab *rewrite_tab;/* Function table */  

static MTX *mtx_first, *mtx_last;  /* Matrix list */
static VAR *var_first, *var_last;  /* Variable list */ 

/*
 * Loops
 */
typedef struct loop_t LOOP;
struct loop_t {
	OBJ(LOOP);
	JUMP_MTX *lp_break;
	JUMP_MTX *lp_cont;
};
static OBUCKET loop_bkt = { sizeof(LOOP), NULL };
static LOOP *loop_first, *loop_last;

void loop_push(MTX *mtx);
void loop_pop();
void loop_fixup(JUMP_MTX *list, MTX *target);
void loop_init();
void loop_free_all();
void loop_unwind_all();

/*
 * Lexical analyzer stuff
 */
static FILE *infile;               /* Input file */ 
static char *input_filename;       /* Input location: file */
static int   input_line;           /* ------------- : line */ 
static int   yyeof;                /* rised when EOF is encountered */ 
static struct obstack input_stk;   /* Symbol stack */ 


/* ***************************************************************
 * Function declarations
 */

/*
 * Lexical analyzer
 */
static void yysync();

/*
 * Frames
 */
static void frame_init();
static void frame_push();
static void frame_pop();
static void frame_unwind_all();
static void frame_free_all();
/*
 * Variables
 */
static void var_init();
static VAR * var_alloc(Datatype type, char *name, int grow);
static void var_unwind_level();
static void var_unwind_all();
static void var_type(Datatype type, VAR *var);
static void var_free_all();
static VAR *var_lookup(char *name);
/*
 * Matrices
 */
static void mtx_init();
static void mtx_free_all();
static void mtx_unwind_all();
static MTX * mtx_cur();
static MTX * mtx_nop();
static MTX * mtx_jump();
static MTX * mtx_frame(Mtxtype type, stkoff_t stksize);
static MTX * mtx_stop();
static MTX * mtx_pop();
static MTX * mtx_return();
static MTX * mtx_alloc(Mtxtype type);
static MTX * mtx_const(Datatype type, void *data);
static MTX * mtx_ref(int num);
static MTX * mtx_var(VAR *var);
static MTX * mtx_asgn(VAR *var, MTX *arg);
static MTX * mtx_bin(Bopcode opcode, MTX *arg1, MTX *arg2);
static MTX * mtx_un(Uopcode opcode, MTX *arg);
static MTX * mtx_match(int negated, MTX *mtx, COMP_REGEX *);
static MTX * mtx_cond(MTX *cond, MTX *if_true, MTX *if_false);
static MTX * mtx_coerce(Datatype type, MTX *arg);
static MTX * mtx_call(FUNCTION *fun, MTX *args);
static MTX * mtx_builtin(builtin_t *bin, MTX *args);
static MTX * mtx_attr(DICT_ATTR *attr);
static MTX * mtx_attr_asgn(DICT_ATTR *attr, MTX *rval);
static MTX * mtx_attr_check(DICT_ATTR *attr);

static MTX * coerce(MTX  *arg, Datatype type);
/*
 * Regular expressions
 */
static COMP_REGEX * rx_alloc(regex_t  *regex, int nmatch);
static void rx_free(COMP_REGEX *rx);
static COMP_REGEX * compile_regexp(char *str);
/*
 * Functions
 */
static FUNCTION * function_install(FUNCTION *fun);
static int  function_free(FUNCTION *fun);
static void function_delete();
static void function_cleanup();
/*
 * Built-in functions
 */
static builtin_t * builtin_lookup(char *name);

/*
 * Code optimizer and generator
 */
static int optimize();
static pctr_t codegen();
static void code_init();

/*
 * Auxiliary and debugging functions
 */
static void debug_dump_code();
static char * datatype_str(Datatype type);
static Datatype attr_datatype(int type);

/*
 * Run-Time
 */
static void gc();
static void run(pctr_t pc);
static void run_init(pctr_t pc, VALUE_PAIR *req);
%}

%union {
	int   number;
	int   type;
	VAR   *var;
	MTX   *mtx;
	FUNCTION  *fun;
	builtin_t *btin;
	DICT_ATTR *attr;
	struct {
		MTX *arg_first;
		MTX *arg_last;
	} arg;
	struct {
		int nmatch;
		regex_t regex;
	} rx;
	char  *string;
};

%token <type>   TYPE
%token IF ELSE RETURN WHILE FOR DO BREAK CONTINUE
%token <string> STRING IDENT
%token <number> NUMBER REFERENCE
%token <var> VARIABLE
%token <fun> FUN
%token <btin> BUILTIN
%token <attr> ATTR
%token BOGUS

%type <arg> arglist 
%type <mtx> stmt expr list cond else while do arg args
%type <var> varlist parmlist parm dclparm


%right '='
%left OR
%left AND
%nonassoc MT NM
%left '|'
%left '^'
%left '&'
%left EQ NE 
%left LT LE GT GE
%left SHL SHR
%left '+' '-'
%left '*' '/' '%'
%left UMINUS NOT TYPECAST

%%

input   : dcllist
          {
		  var_free_all();
		  loop_free_all();
		  frame_free_all();
		  mtx_free_all();
	  }
        ;

dcllist : decl
        | dcllist decl
        | dcllist error
          {
		  /* Roll back all changes done so far */
		  var_unwind_all();
		  loop_unwind_all();
		  frame_unwind_all();
		  mtx_unwind_all();
		  function_delete();
		  /* Synchronize input after error */
		  yysync();
		  /* Clear input and error condition */
		  yyclearin;
		  yyerrok;
		  errcnt = 0;
	  }
        ;

decl    : fundecl begin list end
          {
		  if (errcnt) {
			  function_delete();
			  YYERROR;
		  }
		  
		  if (optimize() == 0) {
			  codegen();
			  if (errcnt) {
				  function_delete();
				  YYERROR;
			  }
		  } else {
			  function_delete();
		  }
		  
		  /* clean up things */
		  var_unwind_all();
		  loop_unwind_all();
		  frame_unwind_all();
		  mtx_unwind_all();
		  function_cleanup();
	  }
        ;

fundecl : TYPE IDENT dclparm
          {
		  VAR *var;
		  PARAMETER *last, *parm;
		  FUNCTION f;
		  
		  if (errcnt)
			  YYERROR;
		  
		  bzero(&f, sizeof(f));
		  f.name    = $2;
		  f.rettype = $1;
		  f.entry   = 0;
		  f.line    = input_line;
		  
		  f.nparm   = 0;
		  f.parm    = NULL;

		  /* Count number of parameters */
		  for (var = $3; var; var = var->next) 
			  f.nparm++;

		  f.parm = last = NULL;
		  for (var = $3; var; var = var->next) {
			  parm = alloc_entry(sizeof(*parm));
			  parm->datatype = var->datatype;
			  var->offset = -(STACK_BASE+
					  f.nparm - var->offset);
			  parm->offset   = var->offset;
			  parm->prev     = last;
			  parm->next     = NULL;
			  if (f.parm == NULL)
				  f.parm = parm;
			  else 
				  last->next = parm;
			  last = parm;
		  }
		  function = function_install(&f);
	  }
        ;

begin   : obrace
        | obrace autodcl
        ;

end     : cbrace
        ;
		  
obrace  : '{'
          {
		  frame_push();
	  }
        ;

cbrace  : '}'
          {
		  var_unwind_level();
		  frame_pop();
	  }
        ;

/*
 * Automatic variables
 */

autodcl : autovar
        | autodcl autovar
        ;

autovar : TYPE varlist ';'
          {
		  var_type($1, $2);
	  }
        ;

varlist : IDENT
          {
		  $$ = var_alloc(Undefined, $1, +1);
		  $$->dcllink = NULL;
	  }
        | varlist ',' IDENT
          {
		  VAR *var = var_alloc(Undefined, $3, +1);
		  var->dcllink = $1;
		  $$ = var;
	  }
        ;

/*
 * Function Parameters
 */
dclparm : '(' ')'
          {
		  $$ = NULL;
	  }
        | '(' parmlist ')'
          {
		  $$ = $2;
	  }
        ;

parmlist: parm
          {
		  /*FIXME*/
		  /*$$->dcllink = NULL;*/
	  }
        | parmlist ',' parm
          {
		  /*$1->dcllink = $3;*/
		  $$ = $1;
	  }
        ;

parm    : TYPE IDENT
          {
		  $$ = var_alloc($1, $2, +1);
	  }
        ;

/* Argument lists
 */

args    : /* empty */
          {
		  $$ = NULL;
	  }
        | arglist
          {
		  $$ = $1.arg_first;
	  }
        ;

arglist : arg
          {
		  $1->gen.arglink = NULL;
		  $$.arg_first = $$.arg_last = $1;
	  }
        | arglist ',' arg
          {
		  $1.arg_last->gen.arglink = $3;
		  $1.arg_last = $3;
		  $$ = $1;
	  }
        ;

arg     : expr
        ;

/*
 * Statement list and individual statements
 */
list    : stmt
        | list stmt
        ;

stmt    : begin list end
          {
		  $$ = $2;
	  }
        | expr ';'
          {
		  mtx_stop();
		  mtx_pop();
	  }
        | IF cond stmt
          {
		  $2->cond.if_false = mtx_nop();
		  $$ = mtx_cur();
	  }
        | IF cond stmt else stmt
          {
		  mtx_stop();
		  $2->cond.if_false = $4;
		  $4->nop.prev->jump.dest = mtx_nop();
		  $$ = mtx_cur();
	  }
        | RETURN expr ';'
          {
		  /*mtx_stop();*/
		  $$ = mtx_return($2);
	  }
        | while cond stmt
	  {
		  MTX *mtx;
		  
	          mtx_stop();
		  mtx = mtx_jump();
		  mtx->jump.dest = $1;
		  $2->cond.if_false = mtx_nop();
		  $$ = mtx_cur();
		  
		  /* Fixup possible breaks */
		  loop_fixup(loop_last->lp_break, $$);
		  /* Fixup possible continues */
		  loop_fixup(loop_last->lp_cont, $1);
		  loop_pop();
	  }	  
	| do stmt { $<mtx>$ = mtx_nop(); } WHILE cond ';' 
          {
		  /* Default cond rule sets if_true to the next NOP matrix
		   * Invert this behaviour.
		   */
		  $5->cond.if_false = $5->cond.if_true;
		  $5->cond.if_true = $1;
		  $$ = mtx_cur();

		  /* Fixup possible breaks */
		  loop_fixup(loop_last->lp_break, $$);
		  /* Fixup possible continues */
		  loop_fixup(loop_last->lp_cont, $<mtx>3);
		  loop_pop();
	  }
/* ***********************
   For the future use:
	| FOR '(' for_expr for_expr for_expr ')' stmt
   *********************** */
        | BREAK ';'
          {
		  if (!loop_last) {
			  radlog(L_ERR,
				 _("%s:%d: nothing to break from"),
				 input_filename, input_line);
			  errcnt++;
			  YYERROR;
		  }

		  $$ = mtx_jump();
		  $$->jump.link = (MTX*)loop_last->lp_break;
		  loop_last->lp_break = (JUMP_MTX*)$$;
	  }
	| CONTINUE ';'
          {
		  if (!loop_last) {
			  radlog(L_ERR,
				 _("%s:%d: nothing to continue"),
				 input_filename, input_line);
			  errcnt++;
			  YYERROR;
		  }
		  $$ = mtx_jump();
		  $$->jump.link = (MTX*)loop_last->lp_cont;
		  loop_last->lp_cont = (JUMP_MTX*)$$;
	  }
        ;

while   : WHILE
          {
		  $$ = mtx_nop();
		  loop_push($$);
	  }
        ;

do      : DO
          {
		  $$ = mtx_nop();
		  loop_push($$);
	  }
        ;

else    : ELSE
          {
		  mtx_stop();
		  mtx_jump();
		  $$ = mtx_nop();
	  }
        ;

cond    : '(' expr ')'
          {
		  mtx_stop();
		  $$ = mtx_cond($2, NULL, NULL);
		  $$->cond.if_true = mtx_nop();
	  }
        ;

/*
 * Expressions
 */
expr    : NUMBER
          {
		  $$ = mtx_const(Integer, &$1);
	  }
        | STRING
          {
		  $$ = mtx_const(String, &$1);
	  }
        | REFERENCE
          {
		  $$ = mtx_ref($1);
	  }
        | VARIABLE
          {
		  $$ = mtx_var($1);
	  }
        | IDENT
          {
		  radlog(L_ERR, "%s:%d: undefined variable: %s",
			 input_filename, input_line, $1);
		  errcnt++;
		  YYERROR;
	  }
        | VARIABLE '=' expr
          {
		  $$ = mtx_asgn($1, $3);
	  }
        | ATTR
          {
		  $$ = mtx_attr($1);
	  }
        | '*' ATTR
          {
		  $$ = mtx_attr_check($2);
	  }
	| ATTR '=' expr
          {
		  $$ = mtx_attr_asgn($1, $3);
	  }
        | FUN '(' args ')'
          {
		  $$ = mtx_call($1, $3);
	  }
        | BUILTIN '(' args ')'
          {
		  $$ = mtx_builtin($1, $3);
	  }
        | expr '+' expr
          {
		  $$ = mtx_bin(Add, $1, $3);
	  }
        | expr '-' expr
          {
		  $$ = mtx_bin(Sub, $1, $3);
	  }
        | expr '*' expr
          {
		  $$ = mtx_bin(Mul, $1, $3);
	  }
        | expr '/' expr
          {
		  $$ = mtx_bin(Div, $1, $3);
	  }
        | expr '%' expr
          {
		  $$ = mtx_bin(Rem, $1, $3);
	  }
        | expr '|' expr
          {
		  $$ = mtx_bin(BOr, $1, $3);
	  }
	| expr '&' expr
          {
		  $$ = mtx_bin(BAnd, $1, $3);
	  }
	| expr '^' expr
          {
		  $$ = mtx_bin(BXor, $1, $3);
	  }
	| expr SHL expr
          {
		  $$ = mtx_bin(Shl, $1, $3);
	  }
	| expr SHR expr
          {
		  $$ = mtx_bin(Shr, $1, $3);
	  }
	| expr AND expr
          {
		  $$ = mtx_bin(And, $1, $3);
	  }
	| expr OR expr
          {
		  $$ = mtx_bin(Or, $1, $3);
	  }
        | '-' expr %prec UMINUS
          {
		  $$ = mtx_un(Neg, $2);
	  }
        | '+' expr %prec UMINUS
          {
		  $$ = $2;
	  }
        | NOT expr
          {
		  $$ = mtx_un(Not, $2);
	  }
        | '(' expr ')'
          {
		  $$ = $2;
	  }
        | '(' TYPE ')' expr %prec TYPECAST
          {
		  $$ = mtx_coerce($2, $4);
	  }
        | expr EQ expr
          {
		  $$ = mtx_bin(Eq, $1, $3);
	  }
        | expr NE expr
          {
		  $$ = mtx_bin(Ne, $1, $3);
	  }
        | expr LT expr
          {
		  $$ = mtx_bin(Lt, $1, $3);
	  }
        | expr LE expr
          {
		  $$ = mtx_bin(Le, $1, $3);
	  }
        | expr GT expr
          {
		  $$ = mtx_bin(Gt, $1, $3);
	  }
        | expr GE expr
          {
		  $$ = mtx_bin(Ge, $1, $3);
	  }
        | expr MT STRING
          {
		  COMP_REGEX *rx;
		  if ((rx = compile_regexp($3)) == NULL) {
			  errcnt++;
			  YYERROR;
		  }
		  $$ = mtx_match(0, $1, rx);
	  }
        | expr NM STRING
          {
		  COMP_REGEX *rx;
		  if ((rx = compile_regexp($3)) == NULL) {
			  errcnt++;
			  YYERROR;
		  }
		  $$ = mtx_match(1, $1, rx);
	  }
        ;

%%

int
yyerror(s)
	char *s;
{
	radlog(L_ERR, "%s:%d: %s",
	       input_filename, input_line, s);
	errcnt++;
}

/* **************************************************************************
 * Interface functions
 */
int
parse_rewrite(path)
	char *path;
{
	input_filename = path;
	infile = fopen(input_filename, "r");
	if (!infile) {
		if (errno != ENOENT) {
			radlog(L_ERR|L_PERROR,
			       _("can't open file `%s'"),
			       input_filename);
		}
		return -1;
	}

	if (!rewrite_tab)
		rewrite_tab = symtab_create(sizeof(FUNCTION), function_free);
	else
		symtab_clear(rewrite_tab);

	yyeof = 0;
	input_line = 1;
	obstack_init(&input_stk);

	code_init();
	mtx_init();
	var_init();
	loop_init();
	frame_init();
	
	frame_push();
	
#if defined(MAINTAINER_MODE) && defined(YACC_DEBUG)
	if (debug_on(50))
		yydebug++;
#endif

	yyparse();

#if defined(MAINTAINER_MODE)
	if (debug_on(100))
		debug_dump_code();
#endif
	
	var_free_all();
	frame_free_all();
	mtx_free_all();
		
	fclose(infile);
	obstack_free(&input_stk, NULL);
	return 0;
}

/* **************************************************************************
 * Lexical analyzer stuff: too simple to be written in lex.
 */
#define unput(c) (c ? ungetc(c, infile) : 0)
static int input();

int
input()
{
	if (yyeof)
		return 0;
	if ((yychar = getc(infile)) <= 0) {
		yyeof++;
		yychar = 0;
	}
	return yychar;
}

static int  rw_backslash();
static int  c2d(int c);
static int  read_number();
static int  read_num(int n, int base);
static char *read_string();
static char *read_ident(int c);
static char *read_to_delim(int c);
static int  skip_to_nl();
static int c_comment();

/*
 * Convert a character to digit. Only octal, decimal and hex digits are
 * allowed. If any other character is input, c2d() returns 100, which is
 * greater than any number base allowed.
 */
int
c2d(c)
	int c;
{
	switch (c) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return c - '0';
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		return c - 'A' + 16;
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return c - 'a' + 10;
	}
	return 100;
}

/*
 * Read a number. Usual C conventions apply. 
 */
int
read_number()
{
	int c;
	int base;

	c = yychar;
	if (c == '0') {
		if (input() == 'x' || yychar == 'X') {
			base = 16;
		} else {
			base = 8;
			unput(yychar);
		}
	} else
		base = 10;
		
	return read_num(c2d(c), base);
}

int
read_num(n, base)
	int n;
	int base;
{
	int d;

	while (input() && (d = c2d(yychar)) < 16) 
		n = n*base + d;
	unput(yychar);
	return n;
}

int
rw_backslash()
{
	switch (input()) {
	case '\\':
		return '\\';
	case 'a':
		return '\a';
	case 'b':
		return '\b';
	case 'f':
		return '\f';
	case 'n':
		return '\n';
	case 'r':
		return '\r';
	case 't':
		return '\t';
	case 'e':
		return '\033';
	case '0':
		return read_number();
	case 'x':
	case 'X':
		return read_num(0, 16);
	case '(':
	case ')':
		/* Preserve regular expressions */
		unput(yychar);
		yychar = '\\';
	}
	return yychar;
}

/*
 * Read a string up to the closing doublequote
 */
char *
read_string()
{
	while (input() && yychar != '"') {
		if (yychar == '\\')
			yychar = rw_backslash();
		obstack_1grow(&input_stk, yychar);
	}
	obstack_1grow(&input_stk, 0);
	return obstack_finish(&input_stk);
}

/*
 * Read everything up to the given delimiter
 */
char *
read_to_delim(c)
	int c;
{
	while (input() && yychar != c)
		obstack_1grow(&input_stk, yychar);
	obstack_1grow(&input_stk, 0);
	return obstack_finish(&input_stk);
}

/*
 * Is `c' a part of the word?
 */
#define isword(c) (isalnum(c) || c == '_' || c == '$')

/*
 * Read identifier
 */
char *
read_ident(c)
	int c;
{
	obstack_1grow(&input_stk, c);
	while (input() && isword(yychar))
		obstack_1grow(&input_stk, yychar);
	obstack_1grow(&input_stk, 0);
	unput(yychar);
	return obstack_finish(&input_stk);
}

/*
 * Skip input up to the next newline
 */
int
skip_to_nl()
{
	while (input() && yychar != '\n')
		;
	return unput(yychar);
}

/*
 * Skip a C-style comment
 */
int
c_comment()
{
	if (yychar != '/')
		return 0;
	if (input() == '*') {
		int keep_line = input_line;

		do {
			while (input() != '*') {
				if (yychar == 0) {
					radlog(L_ERR, 
					       _("%s:%d: unexpected EOF in comment started at line %d"),
					       input_filename,
					       input_line, keep_line);
					return 0;
				} else if (yychar == '\n')
					input_line++;
			}
		} while (input() != '/');
		return 1;
	}
	unput(yychar);
	yychar = '/';
	return 0;
}

#if defined(MAINTAINER_MODE)
# define DEBUG_LEX(s,v) if (debug_on(60)) printf("yylex: " s "\n", v)
#else
# define DEBUG_LEX(s,v)			    
#endif

static struct keyword rw_kw[] = {
	"if",       IF,
	"else",     ELSE,
	"return",   RETURN,
	"for",      FOR,
	"do",       DO,
	"while",    WHILE,
	"break",    BREAK,
	"continue", CONTINUE,
	NULL
};

int
yylex()
{
	int nl;
	int c;
	VAR *var;
	FUNCTION *fun;
	builtin_t *btin;
	
	/* Skip whitespace and comment lines */
	do {
		nl = 0;
		while (input() && isspace(yychar))
			if (yychar == '\n')
				input_line++;
	
		if (!yychar)
			return 0;

		if (yychar == '#') {
			skip_to_nl();
			nl = 1;
		}
	} while (nl || c_comment());

	/*
	 * A regexp reference
	 */
	if (yychar == '\\') {
		input();
		yylval.number = read_number();
		DEBUG_LEX("REFERENCE %d", yylval.number);
		return REFERENCE;
	}

	/*
	 * A character
	 */
	if (yychar == '\'') {
		if (input() == '\\')
			c = rw_backslash();
		else
			c = yychar;
		if (input() != '\'') {
			radlog(L_ERR, "%s:%d: unterminated character constant",
			       input_filename, input_line);
			errcnt++;
		}
		yylval.number = c;
		DEBUG_LEX("CHAR %d", c);
		return NUMBER;
	}
	
	/*
	 * A number
	 */
	if (isdigit(yychar)) {
		yylval.number = read_number();
		DEBUG_LEX("NUMBER %d", yylval.number);
		return NUMBER;
	}

	/*
	 * Quoted string
	 */
	if (yychar == '"') {
		yylval.string = read_string();
		DEBUG_LEX("STRING %s", yylval.string);
		return STRING;
	}

	/* A/V  pair reference.
	   We do not allow %<number> sequences, since it would result
	   in conflict with binary '%' operator.
	   Thanks to Clement Gerouville for noticing.  */
	if (yychar == '%') {
		DICT_ATTR *attr = 0;
		char *attr_name;
		
		input();
		if (yychar == '[' || yychar == '{') {
			attr_name = read_to_delim(yychar == '[' ? ']' : '}');
			attr = attr_name_to_dict(attr_name);
		} else {
			unput(yychar);
			return '%';
		}
		if (!attr) {
			radlog(L_ERR, "%s:%d: unknown attribute",
			       input_filename, input_line);
			errcnt++;
			return BOGUS;
		}
		yylval.attr = attr;
		DEBUG_LEX("ATTR: %s", attr->name);
		return ATTR;
	}
			       
		
	/*
	 * Data type or identifier
	 */
	if (isword(yychar)) {
		yylval.string = read_ident(yychar);

		if (strcmp(yylval.string, "integer") == 0) {
			DEBUG_LEX("TYPE(Integer)", 0);
			yylval.type = Integer;
			return TYPE;
		} else if (strcmp(yylval.string, "string") == 0) {
			DEBUG_LEX("TYPE(String)", 0);
			yylval.type = String;
			return TYPE;
		}

		if ((c = xlat_keyword(rw_kw, yylval.string, 0)) != 0) {
			DEBUG_LEX("KW: %s", yylval.string);
			return c;
		}

		if (var = var_lookup(yylval.string)) {
			DEBUG_LEX("VARIABLE: %s", yylval.string);
			yylval.var = var;
			return VARIABLE;
		}
		
		if (fun = (FUNCTION*) sym_lookup(rewrite_tab, yylval.string)) {
			DEBUG_LEX("FUN %s", yylval.string);
			yylval.fun = fun;
			return FUN;
		}

		if (btin = builtin_lookup(yylval.string)) {
			DEBUG_LEX("BUILTIN %s", yylval.string);
			yylval.btin = btin;
			return BUILTIN;
		}
		DEBUG_LEX("IDENT: %s", yylval.string);
		return IDENT;
	}

	/*
	 * Boolean expressions
	 */
	if (yychar == '&' || yychar == '|') {
		int c = yychar;

		if (input() == c) { 
			DEBUG_LEX("%s", yychar == '&' ? "AND" : "OR"); 
			return yychar == '&' ? AND : OR;
		}
		unput(yychar);
		
		DEBUG_LEX("%c", c); 
		return c;
	}
	
	/*
	 * Comparison operator
	 */
	if (strchr("<>=!", yychar)) {
		int c = yychar;
		if (input() == '=') {
			switch (c) {
			case '<':
				DEBUG_LEX("LE", 0);
				return LE;
			case '>':
				DEBUG_LEX("GE", 0);
				return GE;
			case '=':
				DEBUG_LEX("EQ", 0);
				return EQ;
			case '!':
				DEBUG_LEX("NE", 0);
				return NE;
			}
		} else if (c == yychar) {
			if (c == '<') {
				DEBUG_LEX("SHL", 0);
				return SHL;
			}
			if (c == '>') {
				DEBUG_LEX("SHR", 0);
				return SHR;
			}
			unput(yychar);
			DEBUG_LEX("%c", yychar);
			return yychar;
		} else if (yychar == '~') {
			if (c == '=') {
				DEBUG_LEX("MT", 0);
				return MT;
			}
			if (c == '!') {
				DEBUG_LEX("NM", 0);
				return NM;
			}
		}
		unput(yychar);
		switch (c) {
		case '<':
			DEBUG_LEX("LT", 0);
			return LT;
		case '>':
			DEBUG_LEX("GT", 0);
			return GT;
		case '!':
			DEBUG_LEX("NOT", 0);
			return NOT;
		default:
			return c;
		}
	}

	DEBUG_LEX("%c", yychar);
	return yychar;
}

void
yysync()
{
	while (skip_to_nl() == '\n' && !isalpha(input()))
		input_line++;
	unput(yychar);
}

/* ****************************************************************************
 * Generalized list functions
 */
static LIST *_list_insert(LIST **first, LIST **last, LIST *prev,
			 LIST *obj, int before);
static LIST *_list_remove(LIST **first, LIST **last, LIST *obj);
static LIST *_list_append(LIST **first, LIST **last, LIST *obj);

#define list_insert(first, last, prev, obj, before) \
 _list_insert((LIST**)first,(LIST**)last,(LIST*)prev,(LIST*)obj, before)
#define list_remove(first, last, obj) \
 _list_remove((LIST**)first,(LIST**)last,(LIST *)obj)
#define list_append(first, last, obj) \
 _list_append((LIST**)first, (LIST**)last, (LIST*)obj)
	
LIST *
_list_append(first, last, obj)
	LIST **first, **last, *obj;
{
	return list_insert(first, last, *last, obj, 0);
}

LIST *
_list_insert(first, last, prev, obj, before)
	LIST **first, **last, *prev, *obj;
	int before;
{
	LIST   *next;

	/*
	 * No first element: initialize whole list
	 */
	if (!*first) {
		*first = obj;
		if (last)
			*last = obj;
		obj->prev = obj->next = NULL;
		return obj;
	}

	/*
	 * Insert before `prev'
	 */
	if (before) {
		_list_insert(first, last, prev, obj, 0);
		_list_remove(first, last, prev);
		_list_insert(first, last, obj, prev, 0);
		return obj;
	}

	/*
	 * Default: insert after prev
	 */
	obj->prev = prev;
	obj->next = prev->next;
	
	if (next = prev->next)
		next->prev = obj;

	prev->next = obj;
	if (last && prev == *last)
		*last = obj;

		
	return obj;
}

LIST *
_list_remove(first, last, obj)
	LIST **first, **last, *obj;
{
	LIST *temp;

	if (temp = obj->prev) 
		temp->next = obj->next;
	else
		*first = obj->next;

	if (temp = obj->next)
		temp->prev = obj->prev;
	else if (last)
		*last = obj->prev;

	obj->prev = obj->next = NULL;
	
	return obj;
}

/* ****************************************************************************
 * Generalized object handling
 */

void *obj_alloc(OBUCKET *bucket);
void obj_free_all(OBUCKET *bucket);
 

void *
obj_alloc(bucket)
	OBUCKET *bucket;
{
	OBJECT *optr;

	optr = alloc_entry(bucket->size);

	optr->alloc        = bucket->alloc_list;
	bucket->alloc_list = optr;
	
	return optr;
}

void
obj_free_all(bucket)
	OBUCKET *bucket;
{
	OBJECT *obj, *next;

	obj = bucket->alloc_list;

	while (obj) {
		next = obj->alloc;
		if (bucket->free)
			bucket->free(obj);
		free_entry(obj);
		obj = next;
	}
	bucket->alloc_list = NULL;
}

/* **************************************************************************
 * Frames
 */

void
frame_init()
{
	frame_bkt.alloc_list = NULL;
	frame_first = frame_last = NULL;
}

void
frame_push()
{
	FRAME *this_frame = obj_alloc(&frame_bkt);

	if (!frame_last) {
		this_frame->level = 0;
		this_frame->stack_offset = 0;
	} else {
		if (frame_last->level == 0)
			this_frame->stack_offset = 1;
		else
			this_frame->stack_offset = frame_last->stack_offset;
		this_frame->level = frame_last->level + 1;
	} 
	list_append(&frame_first, &frame_last, this_frame);
}

void
frame_pop()
{
	list_remove(&frame_first, &frame_last, frame_last);
}

void
frame_update_alloc()
{
	FRAME *this_frame = frame_last;

	if (this_frame->stack_offset > function->stack_alloc)
		function->stack_alloc = this_frame->stack_offset;
}

void
frame_free_all()
{
	obj_free_all(&frame_bkt);
	frame_first = frame_last = NULL;
}

void
frame_unwind_all()
{
	while (frame_last)
		list_remove(&frame_first, &frame_last, frame_last);
	frame_push();
}

/* **************************************************************************
 * Loops
 */

void
loop_init()
{
	loop_bkt.alloc_list = NULL;
	loop_first = loop_last = NULL;
}

void
loop_free_all()
{
	obj_free_all(&loop_bkt);
	loop_first = loop_last = NULL;
}

void
loop_unwind_all()
{
	loop_first = loop_last = NULL;
}

/*ARGSUSED*/
void
loop_push(mtx)
	MTX *mtx;
{
	LOOP *this_loop = obj_alloc(&loop_bkt);
	list_append(&loop_first, &loop_last, this_loop);
}

void
loop_pop()
{
	list_remove(&loop_first, &loop_last, loop_last);
}

void
loop_fixup(list, target)
	JUMP_MTX *list;
	MTX *target;
{
	JUMP_MTX *jp;

	for (jp = list; jp; jp = (JUMP_MTX*)jp->link)
		jp->dest = target;
}

/* **************************************************************************
 * Variables
 */
OBUCKET var_bucket = { sizeof(VAR), NULL };

void
var_init()
{
	var_bucket.alloc_list = NULL;
	var_first = var_last = NULL;
}

VAR *
var_alloc(type, name, grow)
	Datatype type;
	char     *name;
	int      grow;
{
	VAR *var;

	var = (VAR*) obj_alloc(&var_bucket);
	list_append(&var_first, &var_last, var);

	/* Initialize fields */
	var->name     = name;
	var->datatype = type; 
	var->level    = curframe->level;
	var->offset   = curframe->stack_offset;
	curframe->stack_offset += grow;

	return var;
}

void
var_unwind_level()
{
	int cnt = 0;
	
	while (var_last && 
	       var_last->level == curframe->level) {
		list_remove(&var_first, &var_last, var_last);
		cnt++;
	}

	if (cnt)
		frame_update_alloc();
}

void
var_unwind_all()
{
	while (var_last)
		list_remove(&var_first, &var_last, var_last);
}

void
var_type(type, var)
	Datatype type;
	VAR      *var;
{
	for (; var; var = var->dcllink)
		var->datatype = type;
}

void
var_free_all()
{
	obj_free_all(&var_bucket);
	var_first = var_last = NULL;
}

VAR *
var_lookup(name)
	char *name;
{
	VAR *var;

	var = var_last;
	while (var && strcmp(var->name, name))
		var = var->prev;
	return var;
}

/* **************************************************************************
 * Matrix generation
 */
OBUCKET mtx_bucket = { sizeof(MTX), NULL };
#if defined(MAINTAINER_MODE)
int mtx_current_id ;
#endif

/*
 * Insert a matrix into list
 */
#define mtx_remove(mtx) list_remove(&mtx_first, &mtx_last, mtx)
#define mtx_append(mtx) list_append(&mtx_first, &mtx_last, mtx)

void
mtx_insert(prev, mtx)
	MTX *prev, *mtx;
{
	MTX *up;

	list_insert(&mtx_first, &mtx_last, prev, mtx, 0);
	if (up = prev->gen.uplink) {
		switch (up->gen.type) {
		case Unary:
			up->un.arg = mtx;
			break;
		case Binary:
			if (up->bin.arg[0] == prev)
				up->bin.arg[0] = mtx;
			else
				up->bin.arg[1] = mtx;
			break;
		case Return:
			up->ret.expr = mtx;
			break;
		default:
			/*should not happen*/
			break;
		}
	}
}

void
mtx_init()
{
	mtx_bucket.alloc_list = NULL;
	mtx_first = mtx_last = NULL;
}

void
mtx_unwind_all()
{
	while (mtx_last)
		list_remove(&mtx_first, &mtx_last, mtx_last);
}

void
mtx_free_all()
{
	obj_free_all(&mtx_bucket);
	mtx_first = mtx_last = NULL;
}

MTX *
mtx_cur()
{
	return mtx_last;
}

MTX *
mtx_frame(type, stksize)
	Mtxtype  type;
	stkoff_t stksize;
{
	FRAME_MTX *mtx = (FRAME_MTX *)mtx_alloc(type);
	mtx_append(mtx);
	mtx->stacksize = stksize;
	return (MTX*)mtx;
}

MTX *
mtx_nop()
{
	MTX *mtx = mtx_alloc(Nop);
	mtx_append(mtx);
	return mtx;
}

MTX *
mtx_jump()
{
	MTX *mtx = mtx_alloc(Jump);
	mtx_append(mtx);
	return mtx;
}

MTX *
mtx_stop()
{
	MTX *mtx = mtx_alloc(Stop);
	mtx_append(mtx);
	return mtx;
}

MTX *
mtx_pop()
{
	MTX *mtx = mtx_alloc(Pop);
	mtx_append(mtx);
	return mtx;
}
	

MTX *
mtx_return(arg)
	MTX   *arg;
{
	MTX *mtx = mtx_alloc(Return);

	mtx_append(mtx);
	mtx->ret.expr = arg;
	arg->gen.uplink = (MTX*)mtx;
	return (MTX*)mtx;
}

/*
 * Allocate a matrix of given type and append it to the list
 */
MTX *
mtx_alloc(type)
	Mtxtype type;
{
	MTX *mtx = obj_alloc(&mtx_bucket);

	mtx->gen.type  = type;
	mtx->gen.line  = input_line;
#if defined(MAINTAINER_MODE)
	mtx->gen.id    = mtx_current_id++;
#endif
	return mtx;
}

/*
 * Create a Constant matrix
 */
MTX *
mtx_const(type, data)
	Datatype type;
	void     *data;
{
	CONST_MTX *mtx = (CONST_MTX *)mtx_alloc(Constant);
	
	mtx_append(mtx);
	mtx->datatype = type;
	switch (type) {
	case Integer:
		mtx->datum.ival = *(int*)data;
		break;
	case String:
		mtx->datum.sval = *(char**)data;
	}
	return (MTX*)mtx;
}

/*
 * Create a Reference matrix
 */
MTX *
mtx_ref(num)
	int num;
{
	MATCHREF_MTX *mtx = (MATCHREF_MTX*)mtx_alloc(Matchref);
	mtx_append(mtx);
	mtx->datatype = String;
	mtx->num = num;
	return (MTX*)mtx;
}

MTX *
mtx_var(var)
	VAR *var;
{
	VAR_MTX *mtx = (VAR_MTX*)mtx_alloc(Variable);
	mtx_append(mtx);
	mtx->datatype = var->datatype; 
	mtx->var = var;
	return (MTX*)mtx;
}

MTX *
mtx_asgn(var, arg)
	VAR *var;
	MTX *arg;
{
	ASGN_MTX *mtx = (ASGN_MTX*)mtx_alloc(Asgn);

	mtx_append(mtx);
	if (var->datatype != arg->gen.datatype)
		coerce(arg, var->datatype);
	mtx->datatype = var->datatype;
	mtx->lval = var;
	mtx->arg  = arg;
	return (MTX*)mtx;
}


Datatype
attr_datatype(type)
	int type;
{
	switch (type) {
	case TYPE_STRING:
	case TYPE_DATE:
		return String;
	case TYPE_INTEGER:
	case TYPE_IPADDR:
		return Integer;
	default:
		insist_fail("unknown attribute type");
	}
	/*NOTREACHED*/
}

MTX *
mtx_attr(attr)
	DICT_ATTR *attr;
{
	ATTR_MTX *mtx = (ATTR_MTX*)mtx_alloc(Attr);
	mtx_append(mtx);
	mtx->attrno   = attr->value;
	mtx->datatype = attr_datatype(attr->type);
	return (MTX*)mtx;
}

MTX *
mtx_attr_check(attr)
	DICT_ATTR *attr;
{
	ATTR_MTX *mtx = (ATTR_MTX*)mtx_alloc(Attr_check);
	mtx_append(mtx);
	mtx->attrno   = attr->value;
	mtx->datatype = Integer;
	return (MTX*)mtx;
}

MTX *
mtx_attr_asgn(attr, rval)
	DICT_ATTR *attr;
	MTX       *rval;
{
	ATTR_MTX *mtx = (ATTR_MTX*)mtx_alloc(Attr_asgn);
	mtx_append(mtx);
	mtx->attrno   = attr->value;
	mtx->datatype = attr_datatype(attr->type);
	if (rval->gen.datatype != mtx->datatype) {
		radlog(L_WARN,
		       "%s:%d: implicit %s to %s coercion",
		       input_filename, input_line,
		       datatype_str(rval->gen.datatype),
		       datatype_str(mtx->datatype));
		rval = coerce(rval, mtx->datatype);
	}
	mtx->rval = rval;
	return (MTX*)mtx;
}

MTX *
mtx_bin(opcode, arg1, arg2)
	Bopcode opcode;
	MTX     *arg1, *arg2;
{
	BIN_MTX *mtx = (BIN_MTX*)mtx_alloc(Binary);

	mtx_append(mtx);
	if (arg1->gen.datatype != arg2->gen.datatype) {
		radlog(L_WARN,"%s:%d: implicit string to integer coercion",
		       input_filename, input_line);
		if (arg1->gen.datatype == String)
			coerce(arg1, Integer);
		else
			coerce(arg2, Integer);
	}

	switch (arg1->gen.datatype) {
	case String:
		switch (opcode) {
		case Add:
			mtx->datatype = String;
			break;
		case Eq:
		case Ne:
		case Lt:
		case Le:
		case Gt:
		case Ge:
			mtx->datatype = Integer;
			break;
		default:
			radlog(L_ERR,
			       "%s:%d: operation not applicable for strings",
			       input_filename, input_line);
			errcnt++;
			return (MTX*)mtx;
		}
		break;
		
	case Integer:
		mtx->datatype = Integer;
	}

	mtx->opcode = opcode;
	mtx->arg[0] = arg1;
	mtx->arg[1] = arg2;
	arg1->gen.uplink = arg2->gen.uplink = (MTX*)mtx;
	return (MTX*)mtx;
}

MTX *
mtx_un(opcode, arg)
	Uopcode opcode;
	MTX     *arg;
{
	UN_MTX *mtx = (UN_MTX*)mtx_alloc(Unary);

	mtx_append(mtx);
	if (arg->gen.datatype != Integer) {
		radlog(L_WARN,"%s:%d: implicit string to integer coercion",
		       input_filename, input_line);
		coerce(arg, Integer);
	}
	mtx->datatype = Integer;
	mtx->opcode = opcode;
	mtx->arg = arg;
	arg->gen.uplink = (MTX*)mtx;
	return (MTX*)mtx;
}

MTX *
mtx_match(negated, arg, rx)
	int        negated;
	MTX        *arg;
	COMP_REGEX *rx;
{
	MATCH_MTX *mtx = (MATCH_MTX*)mtx_alloc(Match);

	mtx_append(mtx);
	if (arg->gen.datatype != String) {
		radlog(L_WARN,"%s:%d: implicit integer to string coercion",
		       input_filename, input_line);
		coerce(arg, String);
	}
	mtx->datatype = Integer;
	mtx->negated = negated;
	mtx->arg = arg;
	mtx->rx  = rx;
	return (MTX*)mtx;
}

MTX *
mtx_cond(cond, if_true, if_false)
	MTX *cond;
	MTX *if_true;
	MTX *if_false;
{
	COND_MTX *mtx = (COND_MTX*)mtx_alloc(Cond);

	mtx_append(mtx);
	mtx->expr = cond;
	mtx->if_true   = if_true;
	mtx->if_false  = if_false;
	return (MTX*)mtx;
}

MTX *
mtx_coerce(type, arg)
	Datatype type;
	MTX      *arg;
{
	if (type == arg->gen.datatype)
		return mtx_cur();
	return coerce(arg, type);
}	

MTX *
coerce(arg, type)
	MTX      *arg;
	Datatype type;
{
	COERCE_MTX *mtx = (COERCE_MTX*)mtx_alloc(Coercion);

	mtx_insert(arg, mtx);
	mtx->datatype = type;
	mtx->arg = arg;
	return (MTX*)mtx;
}

MTX *
mtx_call(fun, args)
	FUNCTION *fun;
	MTX      *args;
{
	MTX       *argp;
	CALL_MTX  *call;
	PARAMETER *parmp;
	int       argn;
	
	/*
	 * Test the number and types of arguments. Insert reasonable
	 * typecasts.
	 */
	argn = 0;
	argp = args;
	parmp = fun->parm;
	while (argp && parmp) {
		if (argp->gen.datatype != parmp->datatype) {
			radlog(L_WARN,
			       "%s:%d: (arg %d) implicit %s to %s coercion",
			       input_filename, input_line,
			       argn,
			       datatype_str(argp->gen.datatype),
			       datatype_str(parmp->datatype));
			coerce(argp, parmp->datatype);
		}
		argn++;
		argp  = argp->gen.arglink;
		parmp = parmp->next;
	}

	/*
	 * Note that the argument count mismatch is not an error!
	 */
	if (argp) {
		radlog(L_WARN,
		       "%s:%d: too many arguments in call to %s",
		       input_filename, input_line,
		       fun->name);
	} else if (parmp) {
		radlog(L_WARN,
		       "%s:%d: too few arguments in call to %s",
		       input_filename, input_line,
		       fun->name);
	}

	call = (CALL_MTX*) mtx_alloc(Call);
	mtx_append((MTX*)call);
	
	call->datatype = fun->rettype;
	call->fun  = fun;
	call->args = args; 
	call->nargs = argn;
	
	return (MTX*) call;
}

MTX *
mtx_builtin(bin, args)
	builtin_t  *bin;
	MTX      *args;
{
	MTX          *argp;
	BTIN_MTX     *call;
	int          argn;
	char         *parmp;
	Datatype     type;
	/*
	 * Test the number and types of arguments. Insert reasonable
	 * typecasts.
	 */
	argn = 0;
	argp = args;
	parmp = bin->parms;
	
	while (argp && parmp) {
		switch (parmp[0]) {
		case 'i':
			type = Integer;
			break;
		case 's':
			type = String;
			break;
		default:
			insist_fail("malformed builtin");
		}

		if (argp->gen.datatype != type) {
			radlog(L_WARN,
			       "%s:%d: (arg %d) implicit %s to %s coercion",
			       input_filename, input_line,
			       argn,
			       datatype_str(argp->gen.datatype),
			       datatype_str(type));
			coerce(argp, type);
		}
		argn++;
		argp  = argp->gen.arglink;
		parmp++;
	}

	if (argp) {
		radlog(L_ERR,
		       "%s:%d: too many arguments in call to %s",
		       input_filename, input_line,
		       bin->name);
		errcnt++;
	} else if (*parmp) {
		radlog(L_ERR,
		       "%s:%d: too few arguments in call to %s",
		       input_filename, input_line,
		       bin->name);
		errcnt++;
	}

	call = (BTIN_MTX*) mtx_alloc(Builtin);
	mtx_append((MTX*)call);
	
	call->datatype = bin->rettype;
	call->fun  = bin->handler;
	call->args = args; 
	call->nargs = argn;
	
	return (MTX*) call;
}

/* ****************************************************************************
 * Code optimizer (rudimentary)
 */


char *
datatype_str(type)
	Datatype type;
{
	switch (type) {
	case Undefined:
		return "Undefined";
	case Integer:
		return "integer";
	case String:
		return "string";
	default:
		return "UNKNOWN";
	}
}

FILE *
debug_open_file()
{
	FILE *fp;
	char *path;
	
	path = mkfilename(radlog_dir, "radius.mtx");
	if ((fp = fopen(path, "a")) == NULL) {
		radlog(L_ERR|L_PERROR,
		       _("can't open file `%s'"),
		       path);
	}
	efree(path);
	return fp;
}

#if defined(MAINTAINER_MODE)

static void debug_print_datum(FILE *fp, Datatype type,	Datum *datum);
static void debug_print_var(FILE *fp, VAR *var);
static void debug_print_unary(FILE *fp, UN_MTX *mtx);
static void debug_print_binary(FILE *fp, BIN_MTX *mtx);
static void debug_print_mtxlist();

static char *b_opstr[] = {
	"Eq",
	"Ne",
	"Lt",
	"Le",
	"Gt",
	"Ge",
	"&",
	"^",
	"|",
	"And",
	"Or",
	"Shl",
	"Shr",
	"Add",
	"Sub",
	"Mul",
	"Div",
	"Rem",
};

static char *u_opstr[] = {
	"Neg",
	"Not"
};

#define LINK(m) (m ? m->gen.id : 0)

void
debug_print_datum(fp, type, datum)
	FILE     *fp;
	Datatype type;
	Datum    *datum;
{
	fprintf(fp, "%3.3s ", datatype_str(type));
	switch (type) {
	case Integer:
		fprintf(fp, "%d", datum->ival);
		break;
	case String:
		fprintf(fp, "%s", datum->sval);
	}
}

void
debug_print_var(fp, var)
	FILE   *fp;
	VAR    *var;
{
	fprintf(fp, "%3.3s %s L:%d S:%d",
		datatype_str(var->datatype),
		var->name,
		var->level,
		var->offset);
	if (var->constant) {
		fprintf(fp, "CONST ");
		debug_print_datum(fp, var->datatype, &var->datum);
	}
}

void
debug_print_unary(fp, mtx)
	FILE   *fp;
	UN_MTX *mtx;
{
	fprintf(fp, "OP:%s M:%d",
		u_opstr[mtx->opcode], LINK(mtx->arg));
}

void
debug_print_binary(fp, mtx)
	FILE     *fp;
	BIN_MTX  *mtx;
{
	fprintf(fp, "OP:%s M1:%d M2:%d",
		b_opstr[mtx->opcode],
		LINK(mtx->arg[0]),
		LINK(mtx->arg[1]));
}


void
debug_print_mtxlist(s)
	char *s;
{
	FILE *fp;
	MTX  *mtx, *tmp;
	
	if ((fp = debug_open_file()) == NULL) 
		return;

	#define CASE(c) case c: fprintf(fp, "%-10.10s", #c);

	fprintf(fp, "%s\n", s);
	for (mtx = mtx_first; mtx; mtx = mtx->gen.next) {
		fprintf(fp, "%4d: %4d %4d ",
			mtx->gen.id,
			LINK(mtx->gen.prev),
			LINK(mtx->gen.next));
		switch (mtx->gen.type) {
		CASE (Generic)
			break;
		CASE (Nop)
			break;
		CASE (Enter)
			fprintf(fp, "%3.3s %d",
				"",
				mtx->frame.stacksize);
			break;
		CASE (Leave)
			fprintf(fp, "%3.3s %d",
				"",
				mtx->frame.stacksize);
			break;
		CASE (Stop)
			break;
		CASE (Constant)
		        debug_print_datum(fp, mtx->cnst.datatype,
					  &mtx->cnst.datum);
		        break;
		CASE (Matchref)
			fprintf(fp, "%3.3s %d",
				datatype_str(String),
				mtx->ref.num);
		        break;
		CASE (Variable)
			debug_print_var(fp, mtx->var.var);
		        break;
		CASE (Unary)
			fprintf(fp, "%3.3s ", datatype_str(mtx->gen.datatype));
			debug_print_unary(fp, &mtx->un);
		        break;
		CASE (Binary)
			fprintf(fp, "%3.3s ", datatype_str(mtx->gen.datatype));
			debug_print_binary(fp, &mtx->bin);
		        break;
		CASE (Cond)
			fprintf(fp, "%3.3s ", "");
			fprintf(fp, "C:%4d T:%4d F:%4d",
				LINK(mtx->cond.expr),
				LINK(mtx->cond.if_true),
				LINK(mtx->cond.if_false));
		        break;
		CASE (Asgn)
			fprintf(fp, "%3.3s ",
				datatype_str(mtx->gen.datatype));
			fprintf(fp, "V:%s,%d,%d M:%4d",
				mtx->asgn.lval->name,
				mtx->asgn.lval->level,
				mtx->asgn.lval->offset,
				LINK(mtx->asgn.arg));
				break;
		CASE (Match)
			fprintf(fp, "    N:%1d M:%4d RX:%p",
				mtx->match.negated,
				LINK(mtx->match.arg),
				mtx->match.rx);
		        break; 
		CASE (Coercion)
			fprintf(fp, "%3.3s M:%4d",
				datatype_str(mtx->coerce.datatype),
				LINK(mtx->coerce.arg));
		        break;
		CASE (Return)
			fprintf(fp, "%3.3s M:%4d",
				datatype_str(mtx->ret.expr->gen.datatype),
				LINK(mtx->ret.expr));
		        break;
		CASE (Jump)
			fprintf(fp, "%3.3s M:%4d",
				"",
				LINK(mtx->jump.dest));
		        break;
		CASE (Branch)
			fprintf(fp, "%3.3s M:%4d",
				mtx->branch.cond ? "NE" : "EQ",
				LINK(mtx->branch.dest));
		        break;
		CASE (Call)
			fprintf(fp, "%3.3s F:%s, A:%d:",
				datatype_str(mtx->call.datatype),
				mtx->call.fun->name,
				mtx->call.fun->nparm);
		        for (tmp = mtx->call.args; tmp; tmp = tmp->gen.arglink)
				fprintf(fp, "%d,", tmp->gen.id);
			break;

		CASE(Builtin)
			fprintf(fp, "%3.3s F:%p, A:%d:",
				datatype_str(mtx->btin.datatype),
				mtx->btin.fun,
				mtx->btin.nargs);
		        for (tmp = mtx->btin.args; tmp; tmp = tmp->gen.arglink)
				fprintf(fp, "%d,", tmp->gen.id);
			break;

		CASE (Pop)
			break;

		CASE (Pusha)
			break;

		CASE (Popa)
			break;
		
       		CASE (Attr)
			fprintf(fp, "%3.3s A:%d",
				datatype_str(mtx->gen.datatype),
				mtx->attr.attrno);
		        break;

       		CASE (Attr_check)
			fprintf(fp, "%3.3s A:%d",
				datatype_str(mtx->gen.datatype),
				mtx->attr.attrno);
		        break;
			
       		CASE (Attr_asgn)
			fprintf(fp, "%3.3s A:%d M:%d",
				datatype_str(mtx->gen.datatype),
				mtx->attr.attrno,
				LINK(mtx->attr.rval));
		        break;
			
		default:
			fprintf(fp, "UNKNOWN: %d", mtx->gen.type);
		}
		fprintf(fp, "\n");
	}			
	
	fclose(fp);
}

void
debug_print_function()
{
	FILE      *fp;
	PARAMETER *parm;
	int        n;
	
	if ((fp = debug_open_file()) == NULL) 
		return;

	fprintf(fp, "FUNCTION: %s\n", function->name);
	fprintf(fp, "RETURNS : %s\n", datatype_str(function->rettype));
	fprintf(fp, "NPARMS  : %d\n", function->nparm);
	fprintf(fp, "PARMS   :\n");

	for (parm = function->parm, n = 0; parm; parm = parm->next, n++) 
		fprintf(fp, "    %4d: %s at %4d\n",
			n, datatype_str(parm->datatype),
			parm->offset);
	
	fclose(fp);
}

#endif /* MAINTAINER_MODE */
	
#if defined(MAINTAINER_MODE)
# define DEBUG_MTX(c) if (debug_on(30))	debug_print_mtxlist(c);
# define DEBUG_FUN()  if (debug_on(25)) debug_print_function();
#else
# define DEBUG_MTX(c) 
# define DEBUG_FUN()
#endif

static void pass1();
static int pass2_unary(MTX *mtx);
static int pass2_binary(MTX *mtx);

void
pass1()
{
	MTX *mtx;
	MTX *end;
	
	/*
	 * Create an entry matrix
	 */
	mtx = mtx_alloc(Enter);
	list_insert(&mtx_first, &mtx_last, mtx_first, mtx, 1);
	mtx->frame.stacksize = function->stack_alloc;
	
	/*
	 * Provide a default return statement if necessary
	 */
	if (mtx_last->gen.type != Return) {
		Datum datum;
		radlog(L_WARN,
		       "%s:%d: missing return statement",
		       input_filename, mtx_last->gen.line);
		switch (function->rettype) {
		case Integer:
			datum.ival = 0;
			break;
		case String:
			datum.sval = "";
		}
		mtx_const(function->rettype, &datum);
		mtx_frame(Leave, function->stack_alloc);
	} else {
		mtx_last->gen.type = Leave;
		mtx_last->frame.stacksize = function->stack_alloc;
	}

	/*
	 * Insert a no-op matrix before the `leave' one
	 */
	end = mtx_alloc(Nop);
	list_insert(&mtx_first, &mtx_last, mtx_last, end, 1);
	
	for (mtx = mtx_first; mtx; mtx = mtx->gen.next) {
		if (mtx->gen.type == Return) {
			if (mtx->ret.expr->gen.datatype != function->rettype) {
				radlog(L_WARN,
				       "%s:%d: implicit %s to %s coercion",
				       input_filename, mtx->ret.line,
				       datatype_str(mtx->ret.expr->gen.datatype),
				       datatype_str(function->rettype));
				coerce(mtx->ret.expr, function->rettype);
			}
			mtx->gen.type = Jump;
			mtx->jump.dest = end;
		}
	}
}
	
/*
 * Second pass: elimination of constant sub-expressions
 */

/*
 * Perform immediate unary calculations
 */
int
pass2_unary(mtx)
	MTX *mtx;
{
	MTX *arg = mtx->un.arg;
	
	switch (mtx->un.opcode) {
	case Not:
		arg->cnst.datum.ival = !arg->cnst.datum.ival;
		break;
	case Neg:
		arg->cnst.datum.ival = -arg->cnst.datum.ival;
		break;
	}
	mtx->gen.type = Constant;
	mtx->cnst.datum = arg->cnst.datum;
	mtx_remove(arg);
	return 0;
}

/*
 * Perform immediate binary computations
 */
int
pass2_binary(mtx)
	MTX *mtx;
{
	MTX *arg0 = mtx->bin.arg[0];
	MTX *arg1 = mtx->bin.arg[1];
	Datum dat;
	
	switch (mtx->bin.opcode) {
	case Eq:
		dat.ival = arg0->cnst.datum.ival == arg1->cnst.datum.ival;
		break;
	case Ne:
		dat.ival = arg0->cnst.datum.ival != arg1->cnst.datum.ival;
		break;
	case Lt:
		dat.ival = arg0->cnst.datum.ival < arg1->cnst.datum.ival;
		break;
	case Le:
		dat.ival = arg0->cnst.datum.ival <= arg1->cnst.datum.ival;
		break;
	case Gt:
		dat.ival = arg0->cnst.datum.ival > arg1->cnst.datum.ival;
		break;
	case Ge:
		dat.ival = arg0->cnst.datum.ival >= arg1->cnst.datum.ival;
		break;
	case BAnd:
		dat.ival = arg0->cnst.datum.ival & arg1->cnst.datum.ival;
		break;
	case BOr:
		dat.ival = arg0->cnst.datum.ival | arg1->cnst.datum.ival;
		break;
	case BXor:
		dat.ival = arg0->cnst.datum.ival ^ arg1->cnst.datum.ival;
		break;
	case And:
		dat.ival = arg0->cnst.datum.ival && arg1->cnst.datum.ival;
		break;
	case Or:
		dat.ival = arg0->cnst.datum.ival || arg1->cnst.datum.ival;
		break;
	case Shl:
		dat.ival = arg0->cnst.datum.ival << arg1->cnst.datum.ival;
		break;
	case Shr:
		dat.ival = arg0->cnst.datum.ival >> arg1->cnst.datum.ival;
		break;
	case Add:
		dat.ival = arg0->cnst.datum.ival + arg1->cnst.datum.ival;
		break;
	case Sub:
		dat.ival = arg0->cnst.datum.ival - arg1->cnst.datum.ival;
		break;
	case Mul:
		dat.ival = arg0->cnst.datum.ival * arg1->cnst.datum.ival;
		break;
	case Div:
		if (arg1->cnst.datum.ival == 0) {
			radlog(L_ERR, "%s:%d: divide by zero",
			       input_filename,
			       arg1->cnst.line);
			errcnt++;
		} else
			dat.ival =
				arg0->cnst.datum.ival / arg1->cnst.datum.ival;
		break;
	case Rem:
		if (arg1->cnst.datum.ival == 0) {
			radlog(L_ERR, "%s:%d: divide by zero",
			       input_filename,
			       arg1->cnst.line);
			errcnt++;
		} else
			dat.ival =
				arg0->cnst.datum.ival % arg1->cnst.datum.ival;
		break;
	}
	mtx->gen.type = Constant;
	mtx->cnst.datum = dat;
	mtx_remove(arg0);
	mtx_remove(arg1);
	return 0;
}

MTX *
mtx_branch(cond, target)
	int cond;
	MTX *target;
{
	MTX *nop = mtx_alloc(Nop);
	MTX *mtx = mtx_alloc(Branch);
	mtx_insert(target, nop);
	mtx->branch.cond = cond;
	mtx->branch.dest = nop;
	return mtx;
}

void
mtx_bool(mtx)
	MTX *mtx;
{
	MTX *j_mtx;

	/*
	 * Insert a j?e after first operand
	 */
	j_mtx = mtx_branch(mtx->bin.opcode == Or, mtx);
	mtx_insert(mtx->bin.arg[0],  j_mtx);
	/*
	 * Remove the op matrix
	 */
	mtx_remove(mtx);
}

/*
 * Second optimization pass: immediate computations
 */
int
pass2()
{
	MTX *mtx, *next;
	int optcnt;
	int errcnt = 0;
	
	do {
		optcnt = 0;
		mtx = mtx_first;
		while (mtx) {
			next = mtx->gen.next;
			switch (mtx->gen.type) {
			case Unary:
				if (mtx->un.arg->gen.type != Constant)
					break;
				if (pass2_unary(mtx))
					errcnt++;
				else
					optcnt++;
				break;
			
			case Binary:
				if (mtx->bin.arg[0]->gen.type == Constant &&
				    mtx->bin.arg[1]->gen.type == Constant) {
					switch (mtx->bin.datatype) {
					case Integer:
						if (pass2_binary(mtx))
							errcnt++;
						else
							optcnt++;
						break;
					case String:
						/*NO STRING OPS SO FAR */;
					}
				} else if (mtx->bin.opcode == And ||
					   mtx->bin.opcode == Or) {
					mtx_bool(mtx);
				}
				break;
				/*FIXME: ADD `if (1)'/`if 0' evaluation */
			case Jump:
				if (mtx->jump.dest == mtx->jump.next)
					mtx_remove(mtx);
			}
			mtx = next;
		}
	} while (errcnt == 0 && optcnt > 0);
	return errcnt;
}

int
optimize()
{
	DEBUG_FUN();
	DEBUG_MTX("on entry to optimize");
	pass1();
	DEBUG_MTX("after first pass");
	if (pass2())
		return -1;
	DEBUG_MTX("after second pass (immediate computations)");
	return 0;
}	

/* ****************************************************************************
 * Code generator
 */

#define RW_REG ('z'-'a'+1)

struct {
	int        reg[RW_REG];       /* Registers */
	#define rA reg[0]
	char       *sA;               /* String accumulator */
	pctr_t     pc;                /* Program counter */  
	
	INSTR      *code;             /* Code segment */
	int        codesize;          /* Length of code segment */ 
	
	int        *stack;            /* Stack+heap space */
	int        stacksize;         /* Size of stack */
	int        st;                /* Top of stack */
	int        sb;                /* Stack base */
	int        ht;                /* Top of heap */
	
	int        nmatch;
	regmatch_t *pmatch;

	VALUE_PAIR *request;
	
	jmp_buf    jmp;
} rw_rt;

void
code_init()
{
	if (rw_rt.code == NULL) {
		rw_rt.codesize  = 4096;
		rw_rt.stacksize = 4096;

		rw_rt.code  = emalloc(rw_rt.codesize * sizeof(rw_rt.code[0]));
		rw_rt.stack = emalloc(rw_rt.stacksize * sizeof(rw_rt.stack[0]));
	}
	/* 0's code element is the default return address */
	rw_rt.pc = 1;
}

#if defined(MAINTAINER_MODE)
void
debug_dump_code()
{
	FILE    *fp;
	pctr_t  pc;
	int     i;
	
	if ((fp = debug_open_file()) == NULL)
		return;
	fprintf(fp, "Code size: %d\n", rw_rt.codesize);
	fprintf(fp, "Code dump:\n");

	pc = 0;
	do {
		fprintf(fp, "%4d:", pc);
		for (i = 0; i < 8 && pc < rw_rt.codesize; i++, pc++)
			fprintf(fp, " %8x", rw_rt.code[pc]);
		fprintf(fp, "\n");
	} while (pc < rw_rt.codesize);
	
	fclose(fp);
}
#endif
/*
 * Runtime function prototypes
 */
static int pushn(int n);
static int cpopn(int *np);
static int popn();
static int checkpop(int cnt);
static int pushref(char *str, int from, int to);
static char *heap_reserve(int size);
static void pushs(int *sptr, int len);
static void pushstr(char *str, int len);

static void rw_pushn();
static void rw_pushs();
static void rw_pushref();
static void rw_pushv();
static void rw_int();
static void rw_string();
static void rw_eq();
static void rw_ne();
static void rw_lt();
static void rw_le();
static void rw_gt();
static void rw_ge();
static void rw_eqs();
static void rw_nes();
static void rw_lts();
static void rw_les();
static void rw_gts();
static void rw_ges();
static void rw_b_xor();
static void rw_b_and();
static void rw_b_or();
static void rw_shl();
static void rw_shr();
static void rw_add();
static void rw_sub();
static void rw_mul();
static void rw_div();
static void rw_rem();
static void rw_not();
static void rw_neg();
static void rw_asgn();
static void rw_enter();
static void rw_leave();
static void rw_match();
static void rw_jmp();
static void rw_jne();
static void rw_je();
static void rw_adds();
static void rw_adjstk();
static void rw_popn();
static void rw_pusha();
static void rw_popa();
static void rw_call();
static void rw_builtin();
static void rw_attrs();
static void rw_attrn();
static void rw_attrcheck();
static void rw_attrasgn();

INSTR bin_codetab[] = {
	rw_eq,              
	rw_ne,
	rw_lt,
	rw_le,
	rw_gt,
	rw_ge,
	rw_b_and,
	rw_b_xor,
	rw_b_or,
	NULL,
	NULL,
	rw_shl,
	rw_shr,
	rw_add,
	rw_sub,
	rw_mul,
	rw_div,
	rw_rem,
};

INSTR bin_string_codetab[] = {
	rw_eqs,                      
	rw_nes,			     
	rw_lts,			     
	rw_les,			     
	rw_gts,			     
	rw_ges,			     
	NULL,			     
	NULL,			     
	NULL,   		     
	NULL,			     
	NULL,			     
	NULL,			     
	NULL,			     
        rw_adds,		     
	NULL,			     
	NULL,			     
	NULL,			     
	NULL			     
};				     

INSTR coerce_tab[] = {
	NULL,
	rw_int,
	rw_string
};

static void check_codesize(int delta);
static int  code(INSTR instr);
static int  data(int val);
static int data_str(char *ptr);
static void add_target(NOP_MTX *mtx, pctr_t pc);


void
add_target(mtx, pc)
	NOP_MTX   *mtx;
	pctr_t    pc;
{
	TGT_MTX *tgt = (TGT_MTX *)mtx_alloc(Target);
	tgt->next = (MTX*)mtx->tgt;
	mtx->tgt = tgt;
	tgt->pc = pc;
}

void
fixup_target(mtx, pc)
	NOP_MTX *mtx;
	pctr_t   pc;
{
	TGT_MTX   *tgt;
	
	for (tgt = (TGT_MTX*)mtx->tgt; tgt; tgt = (TGT_MTX*)tgt->next) 
		rw_rt.code[tgt->pc] = (INSTR)pc;
	mtx->tgt = NULL;
}

pctr_t
codegen()
{
	MTX       *mtx;

	function->entry = rw_rt.pc;
	for (mtx = mtx_first; mtx; mtx = mtx->gen.next) {
		switch (mtx->gen.type) {
		case Generic:
		case Return:
		default:
			radlog(L_CRIT,
			       "INTERNAL ERROR: codegen stumbled accross generic matrix!");
			errcnt++;
			return 0;
		case Nop:
			/* Fix-up the references */
			fixup_target(&mtx->nop, rw_rt.pc);
			mtx->nop.pc = rw_rt.pc;
			break;
		case Stop:
			break;
		case Enter:
			code(rw_enter);
			data(mtx->frame.stacksize);
			break;
		case Leave:
			code(rw_leave);
			break;
		case Constant:
			switch (mtx->cnst.datatype) {
			case Integer:
				code(rw_pushn);
				data(mtx->cnst.datum.ival);
				break;
			case String:
				code(rw_pushs);
				data_str(mtx->cnst.datum.sval);
				break;
			}
			break;
		case Matchref:
			code(rw_pushref);
			data(mtx->ref.num);
			break;
		case Variable:
			/* Variable dereference.
			 */
			code(rw_pushv);
			data(mtx->var.var->offset);
			break;
		case Unary:
			switch (mtx->un.opcode) {
			case Not:
				code(rw_not);
				break;
			case Neg:
				code(rw_neg);
				break;
			}
			break;
		case Binary:
			if (mtx->bin.arg[0]->gen.datatype == String)
				code(bin_string_codetab[mtx->bin.opcode]);
			else
				code(bin_codetab[mtx->bin.opcode]);
			break;
		case Cond:
			/*FIXME: this needs optimization */
			code(rw_jne);
			add_target(&mtx->cond.if_true->nop, rw_rt.pc);
			code(NULL);
			if (mtx->cond.if_false) {
				code(rw_jmp);
				add_target(&mtx->cond.if_false->nop, rw_rt.pc);
				code(NULL);
			}
			break;
			
		case Asgn:
			code(rw_asgn);
			data(mtx->asgn.lval->offset);
			break;
			
		case Match:
			code(rw_match);
			data((int) mtx->match.rx);
			if (mtx->match.negated)
				code(rw_not);
			break;
			
		case Coercion:
			code(coerce_tab[mtx->coerce.datatype]);
			break;
			
		case Jump:
			code(rw_jmp);
			add_target(&mtx->jump.dest->nop, rw_rt.pc);
			code(NULL);
			break;

		case Branch:
			code(mtx->branch.cond ? rw_jne : rw_je);
			add_target(&mtx->branch.dest->nop, rw_rt.pc);
			code(NULL);
			break;
			
		case Call:
			code(rw_call);
			data((int) mtx->call.fun->entry);
			code(rw_adjstk);
			data(mtx->call.nargs);
			break;

		case Builtin:
			code(rw_builtin);
			data((int) mtx->btin.fun);
			code(rw_adjstk);
			data(mtx->btin.nargs);
			break;

		case Pop:
			code(rw_popn);
			break;

		case Popa:
			code(rw_popa);
			break;
			
		case Pusha:
			code(rw_pusha);
			break;
			
		case Attr:
			switch (mtx->attr.datatype) {
			case Integer:
				code(rw_attrn);
				break;
			case String:
				code(rw_attrs);
				break;
			}
			data(mtx->attr.attrno);
			break;

		case Attr_check:
			code(rw_attrcheck);
			data(mtx->attr.attrno);
			break;
			
		case Attr_asgn:
			code(rw_attrasgn);
			data(mtx->attr.attrno);
			break;
				
		}
	}

	/*
	 * Second pass: fixup backward references
	 */
	for (mtx = mtx_first; mtx; mtx = mtx->gen.next) {
		if (mtx->gen.type == Nop)
			fixup_target(&mtx->nop, mtx->nop.pc);
	}
	
#if defined(MAINTAINER_MODE)	
	if (debug_on(25)) {
		FILE *fp = debug_open_file();
		fprintf(fp, "entry: %d, size %d\n",
			function->entry, rw_rt.pc - function->entry);
		fclose(fp);
	}
#endif	
	return function->entry;
}

void
check_codesize(delta)
	int delta;
{
	if (rw_rt.pc + delta >= rw_rt.codesize) {
		INSTR *p = emalloc((rw_rt.codesize + 4096) * sizeof(rw_rt.code[0]));
		memcpy(rw_rt.code, p, rw_rt.codesize);
		efree(rw_rt.code);
		rw_rt.code = p;
		rw_rt.codesize += 4096;
	}
}

int
code(instr)
	INSTR instr;
{
	check_codesize(1);
	rw_rt.code[rw_rt.pc] = instr;
	return rw_rt.pc++;
}

int
data(val)
	int  val;
{
	return code((INSTR)val);
}

int
data_str(ptr)
	char *ptr;
{
	int  len   = strlen(ptr) + 1;
	int  delta = (len + sizeof(rw_rt.code[0])) / sizeof(rw_rt.code[0]);
	
	check_codesize(delta+1);
	rw_rt.code[rw_rt.pc++] = (INSTR)delta;
	memcpy(rw_rt.code + rw_rt.pc, ptr, len);
	rw_rt.pc += delta;
	return rw_rt.pc;
}
	

/* ****************************************************************************
 * Regular expressions
 */

COMP_REGEX *
rx_alloc(regex, nmatch)
	regex_t  *regex;
	int      nmatch;
{
	COMP_REGEX *rx;

	rx = alloc_entry(sizeof(*rx));
	rx->regex  = *regex;
	rx->nmatch = nmatch;
	list_insert(&function->rx_list, NULL, function->rx_list, rx, 1);
	return rx;
}

void
rx_free(rx)
	COMP_REGEX *rx;
{
	COMP_REGEX *next;

	while (rx) {
		next = rx->next;
		regfree(&rx->regex);
		free_entry(rx);
		rx = next;
	}
}

COMP_REGEX *
compile_regexp(str)
	char *str;
{
	char     *p;
	regex_t  regex;
	int      nmatch;
	
	int rc = regcomp(&regex, str, 0);
	if (rc) {
		char errbuf[512];
		regerror(rc, &regex, errbuf, sizeof(errbuf));
		radlog(L_ERR, "%s:%d: regexp error: %s",
		       input_filename, input_line, errbuf);
		return NULL;
	}
	/* count the number of matches */
	nmatch = 0;
	for (p = str; *p; ) {
		if (*p == '\\')
			if (p[1] == '(') {
				nmatch++;
				p += 2;
				continue;
			}
		p++;
	}
	
	return rx_alloc(&regex, nmatch);
}

void
function_delete()
{
	if (function) {
		symtab_delete(rewrite_tab, (Symbol*)function);
		function_cleanup();
	}
}

void
function_cleanup()
{
	function = NULL;
}

/* ****************************************************************************
 * Runtime functions
 */

/*
 * Push a number on stack
 */
int
pushn(n)
	int n;
{
	if (rw_rt.st >= rw_rt.ht) {
		/*FIXME: gc();*/
		debug(1, ("st=%d, ht=%d", rw_rt.st, rw_rt.ht));
		rw_error("rewrite: out of pushdown space");
	}
	rw_rt.stack[rw_rt.st++] = n;
	return 0;
}

/*
 * Push a string on stack
 */
void
pushs(sptr, len)
	int   *sptr;
	int   len;
{
	if (rw_rt.ht - len <= rw_rt.st) {
		/* Heap overrun: */
		/*gc(); */
		rw_error("Heap overrun");
	}

	while (len)
		rw_rt.stack[rw_rt.ht--] = sptr[--len];

	pushn((int) (rw_rt.stack + rw_rt.ht + 1));
}

void
pushstr(str, len)
	char *str;
	int len;
{
	char *s;
	strncpy(s = heap_reserve(len+1), str, len);
	s[len] = 0;
	pushn((int)s);
}

char *
heap_reserve(size)
	int size;
{
	int  len = (size + sizeof(rw_rt.stack[0])) / sizeof(rw_rt.stack[0]);

	if (rw_rt.ht - len <= rw_rt.st) {
		/* Heap overrun: */
		gc();
		if (rw_rt.ht - len <= rw_rt.st) 
			rw_error("Heap overrun");
	}
	rw_rt.ht -= len;
	return (char*)(rw_rt.stack + rw_rt.ht--);
}

/*
 * Pop number from stack and store into NP.
 */
int
cpopn(np)
	int *np;
{
	if (rw_rt.st <= 0) {
		rw_error("rewrite: out of popup");
	}
	*np = rw_rt.stack[--rw_rt.st];
	return 0;
}

/*
 * Pop the number from stack without error checking. A checkpop() function
 * should be called before calling this one.
 */
int
popn()
{
	return rw_rt.stack[--rw_rt.st];
}

int
tos()
{
	return rw_rt.stack[rw_rt.st-1];
}

/*
 * Check if the stack contains at list CNT elements.
 */
int
checkpop(cnt)
	int cnt;
{
	if (rw_rt.st >= cnt)
		return 0;
	rw_error("rw: out of popup");
	/*NOTREACHED*/
}
	
/*
 * Push a backreference value on stack.
 * Arguments: str     --    input string
 *            from    --    start of reference in string
 *            to      --    end of reference in string
 */
int
pushref(str, from, to)
	char *str;
	int   from;
	int   to;
{
	int len = to - from + 1;
	char *s = heap_reserve(len);
	char *p = s;
	
	while (from < to) 
		*p++ = str[from++];
	*p = 0;
	return pushn((int)s);
}

/*
 * Create a stack frame and enter the function
 */
void
enter(n)
	int n;
{
	pushn(rw_rt.sb);
	rw_rt.sb = rw_rt.st;
	rw_rt.st += n;
}

/*
 * Destroy the stack frame and leave the function
 */
void
leave()
{
	/* Save return value */
	rw_rt.rA = popn();
	/* Restore stack frame */
	rw_rt.st = rw_rt.sb;
	rw_rt.sb = popn();
	rw_rt.pc = (pctr_t) popn();
}

int
getarg(num)
	int num;
{
	return rw_rt.stack[rw_rt.sb - (STACK_BASE + num)];
}
/* ****************************************************************************
 * Instructions
 */

static int nil = 0;

int
rw_error(msg)
	char *msg;
{
	radlog(L_ERR,
	       "rewrite runtime error: %s", msg);
	longjmp(rw_rt.jmp, 1);
	/*NOTREACHED*/
}
		
void
rw_call()
{
	pctr_t  pc = (pctr_t) rw_rt.code[rw_rt.pc++];
	pushn(rw_rt.pc); /* save return address */
	rw_rt.pc = pc;
}

void
rw_adjstk()
{
	int delta = (int) rw_rt.code[rw_rt.pc++];
	rw_rt.st -= delta;
	pushn(rw_rt.rA);   /* Push the return back on stack */
}

void
rw_enter()
{
	/*FIXME: runtime checking */
	int n = (int) rw_rt.code[rw_rt.pc++];
	enter(n);
}

void
rw_leave()
{
	leave();
}

/*
 * Push a number on stack
 */
void
rw_pushn()
{
	int  n = (int) rw_rt.code[rw_rt.pc++];
	pushn(n);
}

/*
 * Push a reference value on stack
 */
void
rw_pushref()
{
	int  i = (int) rw_rt.code[rw_rt.pc++];

	pushref(rw_rt.sA, rw_rt.pmatch[i].rm_so, rw_rt.pmatch[i].rm_eo);
}

/*
 * Push a variable on stack
 */
void
rw_pushv()
{
	stkoff_t n = (stkoff_t) rw_rt.code[rw_rt.pc++];

	pushn(rw_rt.stack[rw_rt.sb + n]);
}

void
rw_pushs()
{
	int   len = (int) rw_rt.code[rw_rt.pc++];
	int   *sptr = (int*) rw_rt.code + rw_rt.pc;

	rw_rt.pc += len;
	pushs(sptr, len);
}

/*
 * Assign a value to a variable
 */
void
rw_asgn()
{
	stkoff_t off = (stkoff_t) rw_rt.code[rw_rt.pc++];
	int n;

	cpopn(&n);
	
	rw_rt.stack[rw_rt.sb + off] = n;
	pushn(n);
}

/*
 * Check if the A/V pair is supplied in the request
 */
void
rw_attrcheck()
{
	int attr = (int) rw_rt.code[rw_rt.pc++];

	pushn(avl_find(rw_rt.request, attr) != NULL);
}

/*
 * Assign a value to an A/V pair
 */
void
rw_attrasgn()
{
	int attr = (int) rw_rt.code[rw_rt.pc++];
	int val;
	VALUE_PAIR *pair;
	
	cpopn(&val);
	if ((pair = avl_find(rw_rt.request, attr)) == NULL) {
		pair = avp_create(attr, 0, NULL, 0);
		if (!pair)
			rw_error("can't create A/V pair");
		avl_add_pair(&rw_rt.request, pair);
	}
	switch (pair->type) {
	case TYPE_STRING:
	case TYPE_DATE:
		replace_string(&pair->strvalue, (char*)val);
		pair->strlength = strlen((char*) val);
		break;
	case TYPE_INTEGER:
	case TYPE_IPADDR:
		pair->lvalue = val;
		break;
	}

	pushn(val);
}

void
rw_attrs()
{
	int attr = (int) rw_rt.code[rw_rt.pc++];
	VALUE_PAIR *pair;
	
	if ((pair = avl_find(rw_rt.request, attr)) == NULL) 
		pushs(&nil, 1);
	else
		pushstr(pair->strvalue, pair->strlength);
}

void
rw_attrn()
{
	int attr = (int) rw_rt.code[rw_rt.pc++];
	VALUE_PAIR *pair;

	if ((pair = avl_find(rw_rt.request, attr)) == NULL)
		pushn(0);
	else
		pushn(pair->lvalue);
}

/*
 * Pop (and discard) a value from stack
 */
void
rw_popn()
{
	int n;
	cpopn(&n);
}

/*
 * Pop a value from stack into the accumulator
 */
void
rw_popa()
{
	cpopn(&rw_rt.rA);
}

/*
 * Push accumulator on stack
 */
void
rw_pusha()
{
	pushn(rw_rt.rA);
}

/*
 * String concatenation
 */
void
rw_adds()
{
	char *s1, *s2, *s;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	s = heap_reserve(strlen(s1) + strlen(s2) + 1);
	strcat(strcpy(s, s1), s2);
	pushn((int)s);
}

/*
 * Unary negation
 */
void
rw_neg()
{
	checkpop(1);
	pushn(-popn());
}

/*
 * Bitwise operations
 */
void
rw_b_and()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 & n2);
}

void
rw_b_or()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 | n2);
}

void
rw_b_xor()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 ^ n2);
}

void
rw_shl()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 << n2);
}

void
rw_shr()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 >> n2);
}

/*
 * Addition
 */
void
rw_add()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1+n2);
}

/*
 * Subtraction
 */
void
rw_sub()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1-n2);
}

/*
 * Multiplication
 */
void
rw_mul()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1*n2);
}

/*
 * Division
 */
void
rw_div()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	if (n2 == 0) 
		rw_error("division by zero!");
	pushn(n1/n2);
}

/*
 * Remainder
 */
void
rw_rem()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	if (n2 == 0) 
		rw_error("division by zero!");
	pushn(n1%n2);
}

void
rw_int()
{
	char *s = (char *)popn();
	pushn(strtol(s, NULL, 0));
}

void
rw_string()
{
	int n = popn();
	int buf[64];
	
	snprintf((char*)buf, sizeof(buf), "%d", n);
	pushs(buf, 64);
}

void
rw_eq()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 == n2);
}

void
rw_ne()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 != n2);
}

void
rw_lt()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 < n2);
}

void
rw_le()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 <= n2);
}

void
rw_gt()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 > n2);
}

void
rw_ge()
{
	int n1, n2;

	checkpop(2);
	n2 = popn();
	n1 = popn();
	pushn(n1 >= n2);
}

void
rw_eqs()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) == 0);
}

void
rw_nes()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) != 0);
}

void
rw_lts()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) < 0);
}

void
rw_les()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) <= 0);
}

void
rw_gts()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) > 0);
}

void
rw_ges()
{
	char *s1, *s2;

	checkpop(2);
	s2 = (char*)popn();
	s1 = (char*)popn();
	pushn(strcmp(s1, s2) >= 0);
}

void
rw_not()
{
	int n;

	checkpop(1);
	n = popn();
	pushn(!n);
}

void
rw_match()
{
	COMP_REGEX *rx = (COMP_REGEX *)rw_rt.code[rw_rt.pc++];
	char *s = (char*)popn();
	int rc;
	
	if (rw_rt.nmatch < rx->nmatch + 1) {
		efree(rw_rt.pmatch);
		rw_rt.nmatch = rx->nmatch + 1;
		rw_rt.pmatch = emalloc((rx->nmatch + 1) *
				       sizeof(rw_rt.pmatch[0]));
	}

	rw_rt.sA = s;
	
	rc = regexec(&rx->regex, rw_rt.sA, 
		     rx->nmatch + 1, rw_rt.pmatch, 0);
	if (rc && debug_on(1)) {
		char errbuf[512];
		regerror(rc, &rx->regex,
			 errbuf, sizeof(errbuf));
		radlog(L_DEBUG, "rewrite regex failure: %s. Input: %s",
		       errbuf, (char*)rw_rt.rA);
	}
	pushn(rc == 0);
}

void
rw_jmp()
{
	pctr_t pc = (pctr_t) rw_rt.code[rw_rt.pc++];
	rw_rt.pc = pc;
} 

void
rw_jne()
{
	int n;
	pctr_t pc = (pctr_t) rw_rt.code[rw_rt.pc++];
	
	n = popn();
	if (n != 0)
		rw_rt.pc = pc;
}

void
rw_je()
{
	int n;
	pctr_t pc = (pctr_t) rw_rt.code[rw_rt.pc++];
	
	n = popn();
	if (n == 0)
		rw_rt.pc = pc;
}

void
rw_builtin()
{
	INSTR fun = (INSTR) rw_rt.code[rw_rt.pc++];
	pushn(rw_rt.pc);
	enter(0);
	fun();
	leave();
}

void
run(pc)
	pctr_t pc;
{
	rw_rt.pc = pc;
	while (rw_rt.code[rw_rt.pc]) {
		if (rw_rt.pc >= rw_rt.codesize)
			rw_error("pc out of range");
		(*(rw_rt.code[rw_rt.pc++]))();
	}
}

static int rewrite_call_level = 0;

void
run_init(pc, request)
	pctr_t     pc;
	VALUE_PAIR *request;
{
	FILE *fp;

	if (setjmp(rw_rt.jmp)) {
		rewrite_call_level = 0;
		return;
	}
	
	rw_rt.request = request;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "Before rewriting:\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}
	rw_rt.st = 0;                     /* Stack top */
	rw_rt.ht = rw_rt.stacksize - 1;   /* Heap top */
	/* Imitate a function call */
	rw_rt.pc = 0;
	rw_rt.code[rw_rt.pc++] = NULL;    /* Return address */
	pushn(0);                         /* Push on stack */
	rewrite_call_level = 1;
	run(pc);                          /* call function */
	rewrite_call_level = 0;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "After rewriting\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}
}

/*VARARGS3*/
int
va_run_init(name, request, typestr, va_alist)
	char *name;
	VALUE_PAIR *request;
	char *typestr;
	va_dcl
{
	FILE *fp;
	va_list ap;
	FUNCTION *fun;
	int nargs;
	char *s;
	
	fun = (FUNCTION*) sym_lookup(rewrite_tab, name);
	if (!fun) {
		radlog(L_ERR, _("function %s not defined"), name);
		return -1;
	}
	
	if (setjmp(rw_rt.jmp)) {
		rewrite_call_level = 0;
		return -1;
	}
	
	rw_rt.request = request;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "Before rewriting:\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}
	rw_rt.st = 0;                     /* Stack top */
	rw_rt.ht = rw_rt.stacksize - 1;   /* Heap top */
	rw_rt.pc = 0;

	/* Pass arguments */
	nargs = 0;
	va_start(ap);
	while (*typestr) {
		nargs++;
		switch (*typestr++) {
		case 'i':
			pushn(va_arg(ap, int));
			break;
		case 's':
			s = va_arg(ap, char*);
			pushstr(s, strlen(s));
			break;
		default:
			insist_fail("bad datatype");
		}
	}
	va_end(ap);

	if (fun->nparm != nargs) {
		radlog(L_ERR,
		       _("%s(): wrong number of arguments (should be %d, passed %d"),
		       name, fun->nparm, nargs);
		return -1;
	}

        /* Imitate a function call */
	rw_rt.code[rw_rt.pc++] = NULL;    /* Return address */
	pushn(0);                         /* Push on stack */
	rewrite_call_level = 1;
	run(fun->entry);                  /* call function */
	rewrite_call_level = 0;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "After rewriting\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}
	return rw_rt.rA;
}


int
interpret(fcall, req, type, datum)
	char *fcall;
	RADIUS_REQ *req;
	Datatype *type;
	Datum *datum;
{
	FILE *fp;
	FUNCTION *fun;
	PARAMETER *parm;
	int nargs;
	char **argv = NULL;
	int argc;
	int i, errcnt = 0;
	struct obstack obs;
	char *args;
	
	obstack_init(&obs);
	args = radius_xlate(&obs, fcall, req, NULL);
	if (argcv_get(args, "(),", &argc, &argv) || argc < 3) {
		radlog(L_ERR, _("malformed function call: %s"), fcall);
		obstack_free(&obs, NULL);
		if (argv)
			argcv_free(argc, argv);
		return 1;
	}

        if (argv[1][0] != '(') {
	        radlog(L_ERR, _("missing '(' in function call"));
		errcnt++;
	} 
	if (argv[argc-1][0] != ')') {
		radlog(L_ERR, _("missing ')' in function call"));
		errcnt++;
	}	

	fun = (FUNCTION*) sym_lookup(rewrite_tab, argv[0]);
	if (!fun) {
		radlog(L_ERR, _("function %s not defined"), argv[0]);
		errcnt++;
	}

	if (errcnt) {
		obstack_free(&obs, NULL);
		argcv_free(argc, argv);
		return 1;
	}
	
	rw_rt.request = req ? req->request : NULL;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "Before rewriting:\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}

	if (rewrite_call_level == 0) {
		rw_rt.st = 0;                     /* Stack top */
		rw_rt.ht = rw_rt.stacksize - 1;   /* Heap top */
		rw_rt.pc = 0;
	}

	/* Pass arguments */
	nargs = 0;
	parm = fun->parm;

	for (i = 2; i < argc-1; i++) {
		int n;
		char *p;
		
		if (i % 2) {
			if (argv[i][0] == ',')
				continue;
			radlog(L_ERR,
		        "calling %s: expected ',' but found %s after arg %d",
			       argv[0], argv[i], parm);
			obstack_free(&obs, NULL);
			argcv_free(argc, argv);
			return -1;
		}

		if (++nargs > fun->nparm) {
			radlog(L_ERR, "too many arguments for %s", argv[0]);
			obstack_free(&obs, NULL);
			argcv_free(argc, argv);
			return -1;
		}

		switch (parm->datatype) {
		case Integer:
			n = strtol(argv[i], &p, 0);
			if (*p) 
				n = get_ipaddr(argv[i]);
			pushn(n);
			break;
		case String:
			pushstr(argv[i], strlen(argv[i]));
			break;
		default:
			insist_fail("datatype!");
		}
		parm = parm->next;
	}
	obstack_free(&obs, NULL);
	
	if (fun->nparm != nargs) {
		radlog(L_ERR,
		       _("too few arguments for %s"),
			 argv[0]);
		argcv_free(argc, argv);
		return -1;
	}

	argcv_free(argc, argv);

	++rewrite_call_level;
	
        /* Imitate a function call */
	if (setjmp(rw_rt.jmp)) {
		--rewrite_call_level;
		return -1;
	}
	
	rw_rt.code[rw_rt.pc++] = NULL;    /* Return address */
	pushn(0);                         /* Push on stack */
	run(fun->entry);                  /* call function */
	--rewrite_call_level;
	if (debug_on(2)) {
		fp = debug_open_file();
		fprintf(fp, "After rewriting\n");
		avl_fprint(fp, rw_rt.request);
		fclose(fp);
	}
	
	switch (fun->rettype) {
	case Integer:	
		datum->ival = rw_rt.rA;
		break;
	case String:
		datum->sval = (char*) rw_rt.rA;
		break;
	default:
		abort();
	}
	*type = fun->rettype;
	return 0;
}

int
run_rewrite(name, req)
	char *name;
	VALUE_PAIR *req;
{
	FUNCTION *fun;
	
	fun = (FUNCTION*) sym_lookup(rewrite_tab, name);
	if (fun) {
		if (fun->nparm) {
			radlog(L_ERR, "function %s() requires %d parameters",
			       fun->name, fun->nparm);
			return -1;
		}
		run_init(fun->entry, req);
		return 0;
	} 
	return -1;
}

/* ****************************************************************************
 * A placeholder for the garbage collector
 */

void
gc()
{
}

/* ****************************************************************************
 * Built-in functions
 */

static void bi_length();
static void bi_index();
static void bi_rindex();
static void bi_substr();
static void bi_field();
static void bi_logit();

/*
 * integer length(string s)
 */
void
bi_length()
{
	pushn(strlen((char*)getarg(1)));
}

/*
 * integer index(string s, integer a)
 */
void
bi_index()
{
	char *s, *p;
	int   c;

	s = (char*)getarg(2);
	c = (int) getarg(1);
	p = strchr(s, c);
	pushn( p ? p - s : -1 );
}

/*
 * integer rindex(string s, integer a)
 */
void
bi_rindex()
{
	char *s, *p;
	int   c;

	s = (char*)getarg(2);
	c = (int) getarg(1);
	pushn( (p = strrchr(s, c)) ? p - s : -1 );
}

/*
 * integer substr(string s, int start, int length)
 */
void
bi_substr()
{
	char *src, *dest;
	int   start, length;

	src    = (char*)getarg(3);
	start  = getarg(2);
	length = getarg(1);
	if (length < 0)
		length = strlen(src) - start;
	
	dest = heap_reserve(length+1);
	if (length > 0) 
		strncpy(dest, src + start, length);
	dest[length] = 0;
	pushn((int) dest);
}

void
bi_field()
{
	char *str = (char*)getarg(2);
	int fn = getarg(1);
	char *s = (char*)&nil;
	int len = 1;

	while (fn--) {
		/* skip initial whitespace */
		while (*str && isspace(*str))
			str++;

		s = str;
		len = 0;
		while (*str && !isspace(*str)) {
			str++;
			len++;
		}
	}

	str = heap_reserve(len+1);
	if (len) {
		memcpy(str, s, len);
		str[len] = 0;
	}
	pushn((int) str);
}

void
bi_logit()
{
	char *msg = (char*)getarg(1);
	radlog(L_INFO, "%s", msg);
	pushn(0);
}

static builtin_t builtin[] = {
	bi_length,  "length", Integer, "s",
	bi_index,   "index",  Integer, "si",
	bi_rindex,  "rindex", Integer, "si",
	bi_substr,  "substr", String,  "sii",
	bi_logit,   "logit",  Integer, "s",
	bi_field,   "field",  String,  "si",
	NULL
};

builtin_t *
builtin_lookup(name)
	char *name;
{
	int i;

	for (i = 0; builtin[i].handler; i++)
		if (strcmp(name, builtin[i].name) == 0)
			return &builtin[i];
	return NULL;
}

/* ****************************************************************************
 * Function registering/unregistering 
 */

int
function_free(f)
	FUNCTION *f;
{
	PARAMETER *parm, *next;
	
	rx_free(f->rx_list);
	parm = f->parm;
	while (parm) {
		next = parm->next;
		free_entry(parm);
		parm = next;
	}
	return 0;
}
		
FUNCTION *
function_install(fun)
	FUNCTION *fun;
{
	FUNCTION *fp;

	if (fp = (FUNCTION *)sym_lookup(rewrite_tab, fun->name)) {
		radlog(L_ERR,
		       "%s:%d: redefinition of function %s",
		       input_filename, fun->line, fun->name);
		radlog(L_ERR,
		       "%s:%d: previuosly defined here",
		       input_filename, fun->line);
		errcnt++;
		return fp;
	}  
	fp = (FUNCTION*)sym_install(rewrite_tab, fun->name);
	
	fp->rettype = fun->rettype;
	fp->entry   = fun->entry;
	fp->rx_list = fun->rx_list;
	fp->nparm   = fun->nparm;        
	fp->parm    = fun->parm;
	fp->stack_alloc = fun->stack_alloc;
	return fp;
}

/* ****************************************************************************
 * Guile interface
 */
#ifdef USE_SERVER_GUILE

SCM
radscm_datum_to_scm(type, datum)
	int type;
	Datum datum;
{
	switch (type) {
	case Integer:
		return scm_makenum(datum.ival);

	case String:
		return scm_makfrom0str(datum.sval);

	}
	return SCM_UNSPECIFIED;
}

int
radscm_scm_to_ival(cell, val)
	SCM cell;
	int *val;
{
	if (SCM_IMP(cell)) {
		if (SCM_INUMP(cell))  
			*val = SCM_INUM(cell);
		else if (SCM_BIGP(cell)) 
			*val = (UINT4) scm_big2dbl(cell);
		else if (SCM_CHARP(cell))
			*val = SCM_CHAR(cell);
		else if (cell == SCM_BOOL_F)
			*val = 0;
		else if (cell == SCM_BOOL_T)
			*val = 1;
		else if (cell == SCM_EOL)
			*val =0;
		else
			return -1;
	} else {
		if (SCM_STRINGP(cell)) {
			char *p;
			*val = strtol(SCM_ROCHARS(cell), &p, 0);
			if (*p)
				return -1;
		} else
			return -1;
	}
	return 0;
}

SCM
radscm_rewrite_execute(char *func_name, SCM ARGS)
{
	char *name;
	FUNCTION *fun;
	PARAMETER *parm;
	int nargs;
	int n, rc;
	Datum datum;
	SCM cell;
	SCM FNAME;

	FNAME = SCM_CAR(ARGS);
	ARGS  = SCM_CDR(ARGS);
	SCM_ASSERT(SCM_NIMP(FNAME) && SCM_STRINGP(FNAME),
		   FNAME, SCM_ARG1, func_name);

	name = SCM_ROCHARS(FNAME);
	fun = (FUNCTION*) sym_lookup(rewrite_tab, name);
	if (!fun) 
		scm_misc_error(func_name,
			       "function ~S not defined",
			       SCM_LIST1(FNAME));

	if (rewrite_call_level == 0) {
		rw_rt.st = 0;                     /* Stack top */
		rw_rt.ht = rw_rt.stacksize - 1;   /* Heap top */
		rw_rt.pc = 0;
	}

	/* Pass arguments */
	nargs = 0;
	parm = fun->parm;
	
	for (cell = ARGS; cell != SCM_EOL; cell = SCM_CDR(cell), parm = parm->next) {
		SCM car = SCM_CAR(cell);

		if (++nargs > fun->nparm) {
			scm_misc_error(func_name,
				       "too many arguments for ~S",
				       SCM_LIST1(FNAME));
		}

		switch (parm->datatype) {
		case Integer:
			rc = radscm_scm_to_ival(car, &n);
			if (!rc) 
				pushn(n);
			break;
			
		case String:
			if (SCM_NIMP(car) && SCM_STRINGP(car)) {
				char *p = SCM_ROCHARS(car);
				pushstr(p, strlen(p));
				rc = 0;
			} else
				rc = 1;
		}

		if (rc) 
			scm_misc_error(func_name,
			     "type mismatch in argument ~S(~S) in call to ~S",
				       SCM_LIST3(SCM_MAKINUM(nargs),
						 car,
						 FNAME));
	}

	if (fun->nparm != nargs)
		scm_misc_error(func_name,
			       "too few arguments for ~S",
			       SCM_LIST1(FNAME));

	/* Imitate a function call */
	++rewrite_call_level;
	if (setjmp(rw_rt.jmp)) {
		--rewrite_call_level;
		return -1;
	}
	rw_rt.code[rw_rt.pc++] = NULL;    /* Return address */
	pushn(0);                         /* Push on stack */
	run(fun->entry);                  /* call function */
	--rewrite_call_level;

	switch (fun->rettype) {
	case Integer:	
		datum.ival = rw_rt.rA;
		break;
	case String:
		datum.sval = (char*) rw_rt.rA;
		break;
	default:
		abort();
	}

	return radscm_datum_to_scm(fun->rettype, datum);
}


#endif

	/*HONY SOIT QUI MAL Y PENSE*/
