%{
/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

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

extern grad_locus_t source_locus;

char *print_ident(Variable *var);
int subscript(Variable *var, char *attr_name, int all, Variable *ret_var);

int yyerror(char *s);

extern int yylex();

%}

%token EOL AUTH ACCT SEND EXPECT
%token EQ LT GT NE LE GE
%token PRINT 
%token EXIT
%token <ident> IDENT
%token <string> NAME
%token <number> NUMBER
%token <string> QUOTE
%token <ipaddr> IPADDRESS

%type <number> code 
%type <op> op
%type <variable> value expr send_flag
%type <ident> maybe_expr 
%type <symtab> send_flags send_flag_list
%type <vector> vector 
%type <pair_list> pair_list
%type <pair> pair
%type <string> string 
%type <number> port_type

%union {
        char *string;
        int number;
        grad_uint32_t ipaddr;
        Variable *ident;
        grad_avp_t *pair;
        grad_avp_t *vector;
        struct {
                grad_avp_t *head, *tail;
        } pair_list;
        Variable variable;
	grad_symtab_t *symtab;
	enum grad_operator op;
}

%%

input         : list
              ;

list          : stmt
              | list stmt
              ;

stmt          : /* empty */ EOL
              | PRINT prlist EOL
                {
                        printf("\n");
                }
              | NAME EQ expr EOL
                {
                        Variable *var;
                        
                        if ((var = (Variable*) grad_sym_lookup(vartab, $1)) == NULL)
                                var = (Variable*) grad_sym_install(vartab, $1);
                        if (var->type == Builtin)
                                var->datum.builtin.set(&$3);
                        else {
                                var->type = $3.type;
                                var->datum = $3.datum;
                        }
                }
              | SEND send_flags port_type code maybe_expr EOL
                {
                        radtest_send($3, $4, $5, $2);
                        tempvar_free($5);
			grad_symtab_free(&$2);
                }
              | EXPECT code maybe_expr EOL
                {
                        int pass = 1;
                        if (verbose) {
                                printf("expect %d\n", $2);
                                printf("got    %d\n", reply_code);
                        }
                        if (reply_code != $2) {
                                if (abort_on_failure) {
                                        parse_error("expect failed: got %d\n",
                                                    reply_code);
                                        YYACCEPT;
                                }
                                pass = 0;
                        }
                        if ($3) {
                                if ($3->type != Vector) {
                                        parse_error("expecting vector");
                                        YYERROR;
                                }
                                if (compare_lists(reply_list,
                                                  $3->datum.vector))
                                        pass = 0;
                                tempvar_free($3);
                                grad_free($3);
                        }
                        printf("%s\n", pass ? "PASS" : "FAIL");
                } 
              | error EOL
                {
                        yyclearin;
                        yyerrok;
                }
              | EXIT
                {
                        YYACCEPT;
                }
              ;

port_type     : AUTH
                {
                        $$ = PORT_AUTH;
                }
              | ACCT
                {
                        $$ = PORT_ACCT;
                }
              ;

code          : NUMBER
              | NAME
                {
			$$ = grad_string_to_request_code($1);
			if ($$ == 0) {
				yyerror("expected integer value or request code name");
				YYERROR;
			}
		}
              | IDENT
                {
                        if ($1->type != Integer) {
                                yyerror("expected integer value or request code name");
                                YYERROR;
                        } else {
                                $$ = $1->datum.number;
                        }
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
			Variable *var;
			
			$$ = grad_symtab_create(sizeof(Variable), var_free);
			var = (Variable*) grad_sym_install($$, $1.name);
			var->type = $1.type;
			var->datum = $1.datum;
		}
              | send_flag_list send_flag
                {
			Variable *var;
			var = (Variable*) grad_sym_install($1, $2.name);
			var->type = $2.type;
			var->datum = $2.datum;
			$$ = $1;
		}
              ;

send_flag     : NAME EQ NUMBER
                {
                        $$.name = $1;
                        $$.type = Integer;
                        $$.datum.number = $3;
		}
              ;

expr          : value
              | expr '+' value 
                {
                        if ($1.type != Vector) {
                                parse_error("bad datatype of larg in +");
                        } else if ($3.type != Vector) {
                                parse_error("bad datatype of rarg in +");
                        } else {
                                grad_avl_add_list(&$1.datum.vector,
						  $3.datum.vector);
                                $$ = $1;
                        }
                }
              ;

maybe_expr    : /* empty */
                {
                        $$ = NULL;
                }
              | expr
                {
			$$ = grad_emalloc(sizeof(*$$));
                        *$$ = $1;
                }
              ;

vector        : pair_list
                {
                        $$ = $1.head;
                }
              ;

pair_list     : pair
                {
                        $$.head = $$.tail = $1;
                }
              | pair_list pair
                {
                        if ($2) {
                                if ($$.tail) {
                                        $$.tail->next = $2;
                                } else {
                                        $$.head = $2;
                                }
				for ($$.tail = $2; $$.tail->next; $$.tail = $$.tail->next)
					;	
                        } 
                }
              | pair_list ',' pair
                {
                        if ($3) {
                                if ($$.tail) {
                                        $$.tail->next = $3;
                                        $$.tail = $3;
                                } else {
                                        $$.head = $$.tail = $3;
                                }
                        }
                }
              | pair_list error 
                {
                        grad_avl_free($1.head);
                        $$.head = $$.tail = NULL;
                }
              ;

pair          : NAME op string
                {
                        $$ = grad_create_pair(&source_locus, $1, $2, $3);
                        grad_free($3);
                }
              ;

string        : QUOTE
              | NAME
              | NUMBER
                {
                        char buf[64];
                        sprintf(buf, "%d", $1);
                        $$ = grad_estrdup(buf);
                }
              | IDENT
                {
                        $$ = print_ident($1);
                }
              | IPADDRESS
                {
                        char buf[DOTTED_QUAD_LEN];
                        grad_ip_iptostr($1, buf);
                        $$ = grad_estrdup(buf);
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

value         : NUMBER
                {
                        $$.name = NULL;
                        $$.type = Integer;
                        $$.datum.number = $1;
                }
              | IPADDRESS
                {
                        $$.name = NULL;
                        $$.type = Ipaddress;
                        $$.datum.ipaddr = $1;
                }
              | QUOTE
                {
                        $$.name = NULL;
                        $$.type = String;
                        $$.datum.string = grad_estrdup($1);
                }
              | IDENT
                {
                        $$ = *$1;
                }
              | IDENT '[' NAME ']'
                {
                        $$.name = NULL;
                        subscript($1, $3, 0, &$$);
                }
              | IDENT '[' NAME '*' ']'
                {
                        $$.name = NULL;
                        subscript($1, $3, 1, &$$);
                }
              | vector
                {
                        $$.name = NULL;
                        $$.type = Vector;
                        $$.datum.vector = $1;
                }
              ;

prlist        : pritem
              | prlist pritem
              ;

pritem        : expr
                {
                        var_print(&$1);
                        tempvar_free(&$1);
                }
              ;

%%

int
yyerror(char *s)
{
        fprintf(stderr, "%s:%lu: %s\n",
                source_locus.file, (unsigned long) source_locus.line,
                s);
}

void
parse_error(const char *fmt, ...)
{
        va_list ap;

	va_start(ap, fmt);
        fprintf(stderr, "%s:%lu: ", source_locus.file, source_locus.line);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
}

void
set_yydebug()
{
        extern int yydebug;
        if (debug_on(1)) {
                yydebug = 1;
        }
}

int
subscript(Variable *var, char *attr_name, int all, Variable *ret_var)
{
        grad_dict_attr_t *dict;
        grad_avp_t *pair;

        ret_var->type = Undefined;
        if (var->type != Vector) {
                parse_error("subscript on non-vector");
                return -1;
        }
        if ((dict = grad_attr_name_to_dict(attr_name)) == NULL) {
                parse_error("unknown attribute %s", attr_name);
                return -1;
        }
        
        pair = grad_avl_find(var->datum.vector, dict->value);
        if (!pair) 
                return -1;

        switch (dict->type) {
        case TYPE_STRING:
                ret_var->type = String;
                if (all) {
                        int length = 0;
                        grad_avp_t *p;
                        char *cp;
                        
                        /* First, count total length of all attribute
                           instances in the packet */
                        for (p = pair; p;
			     p = grad_avl_find(p->next, dict->value)) 
                                length += p->avp_strlength;

                        cp = ret_var->datum.string = grad_emalloc(length+1);
                        /* Fill in the string contents */
                        for (p = pair; p;
			     p = grad_avl_find(p->next, dict->value)) {
                                memcpy(cp, p->avp_strvalue, p->avp_strlength);
                                cp += p->avp_strlength;
                        }
                        *cp = 0;
                } else
                        ret_var->datum.string = grad_estrdup(pair->avp_strvalue);
                break;
        case TYPE_INTEGER:
        case TYPE_DATE:
                ret_var->type = Integer;
                ret_var->datum.number = pair->avp_lvalue;
                break;
        case TYPE_IPADDR:
                ret_var->type = Ipaddress;
                ret_var->datum.ipaddr = pair->avp_lvalue;
                break;
        default:
                grad_log(L_CRIT,
                         _("attribute %s has unknown type"),
                         dict->name);
                exit(1);
        }
        return 0;
}

