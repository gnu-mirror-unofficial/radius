%{
/* This file is part of GNU RADIUS.
   Copyright (C) 2000, 2001, Sergey Poznyakoff
  
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

#define RADIUS_MODULE_GRAM
	
#ifndef lint	
static char rcsid[] = 
	"@(#) $Id$";
#endif	
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
#include <varargs.h>
#include <sysdep.h>
#include <radius.h>
#include <radclient.h>
#include <radtest.h>
#include <debugmod.h>

int source_line_num;
char *source_filename = "";

char *print_ident(Variable *var);
int subscript(Variable *var, char *attr_name, int all, Variable *ret_var);

%}

%token EOL AUTH ACCT SEND EXPECT
%token EQ LT GT NE LE GE
%token PRINT ALL VARS
%token EXIT
%token <ident> IDENT
%token <string> NAME
%token <number> NUMBER
%token <string> QUOTE
%token <ipaddr> IPADDRESS

%type <number> op code 
%type <variable> value expr
%type <ident> maybe_expr
%type <vector> vector 
%type <pair_list> pair_list
%type <pair> pair
%type <string> string 
%type <number> port_type

%union {
	char *string;
	int number;
	UINT4 ipaddr;
	Variable *ident;
	VALUE_PAIR *pair;
	VALUE_PAIR *vector;
	struct {
		VALUE_PAIR *head, *tail;
	} pair_list;
	Variable variable;
}

%%

input         : { prompt(); } list
              ;

list          : stmt
                {
			prompt();
		}
              | list stmt
                {
			prompt();
		}
              ;

stmt          : /* empty */ EOL
              | PRINT prlist EOL
                {
			printf("\n");
		}
              | NAME EQ expr EOL
                {
			Variable *var;
			
			if ((var = (Variable*) sym_lookup(vartab, $1)) == NULL)
				var = (Variable*) sym_install(vartab, $1);
			if (var->type == Builtin)
				var->datum.builtin.set(&$3);
			else {
				var->type = $3.type;
				var->datum = $3.datum;
			}
		}
              | SEND port_type code expr EOL
                {
			radtest_send($2, $3, &$4);
		}
              | EXPECT code maybe_expr EOL
                {
			int pass = 1;
			if (verbose) {
				printf("expect %d\n", $2);
				printf("got    %d\n", reply_code);
			}
			if (reply_code != $2) {
				parse_error("expect failed: got %d\n",
					    reply_code);
				if (abort_on_failure)
					YYACCEPT;
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
				/*FIXME: free $3 */
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
              | IDENT
                {
			if ($1->type != Integer) {
				yyerror("expected integer value");
				YYERROR;
			} else {
				$$ = $1->datum.number;
			}
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
				avl_add_list(&$1.datum.vector, $3.datum.vector);
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
			$$ = emalloc(sizeof(*$$));
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
 					$$.tail = $2;	
 				} else {
 					$$.head = $$.tail = $2;
 				}
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
			avl_free($1.head);
			$$.head = $$.tail = NULL;
		}
              ;

pair          : NAME op string
                {
			$$ = install_pair($1, $2, $3);   
	        }
              ;

string        : QUOTE
              | NAME
              | NUMBER
                {
			char buf[64];
			sprintf(buf, "%d", $1);
			$$ = make_string(buf);
	        }
              | IDENT
                {
			$$ = print_ident($1);
		}
              | IPADDRESS
                {
			char buf[DOTTED_QUAD_LEN];
			ipaddr2str(buf, $1);
			$$ = make_string(buf);
		}
              ;

op            : EQ
                {
			$$ = OPERATOR_EQUAL;
		} 
              | LT
                {
			$$ = OPERATOR_LESS_THAN;
		}
              | GT
                { 
			$$ = OPERATOR_GREATER_THAN;
		}
              | NE
                {
			$$ = OPERATOR_NOT_EQUAL;
		}
              | LE
                {
			$$ = OPERATOR_LESS_EQUAL;
		}
              | GE
                {
			$$ = OPERATOR_GREATER_EQUAL;
		}
              ;

value         : NUMBER
                {
			$$.type = Integer;
			$$.datum.number = $1;
		}
              | IPADDRESS
                {
			$$.type = Ipaddress;
			$$.datum.ipaddr = $1;
		}
              | QUOTE
                {
			$$.type = String;
			$$.datum.string = make_string($1);
		}
              | IDENT
                {
			$$ = *$1;
		}
              | IDENT '[' NAME ']'
                {
			subscript($1, $3, 0, &$$);
		}
              | IDENT '[' NAME '*' ']'
                {
			subscript($1, $3, 1, &$$);
		}
              | vector
                {
			$$.type = Vector;
			$$.datum.vector = $1;
		}
              ;

prlist        : pritem
              | prlist pritem
              ;

pritem        : expr
                {
		        print(&$1);
	        }
	      ;

%%

yyerror(s)
	char *s;
{
	fprintf(stderr, "%s:%d: %s\n",
		source_filename,
		source_line_num,
		s);
}

void
parse_error(va_alist)
	va_dcl
{
	va_list ap;
	char *fmt;
	
	va_start(ap);
	fmt = va_arg(ap, char*);
	fprintf(stderr, "%s:%d: ", source_filename, source_line_num);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void
set_yydebug()
{
	extern int yydebug;
	if (debug_on(1)) {
#ifdef YACC_DEBUG
		yydebug = 1;
#else
		fprintf(stderr, "radtest compiled without parser debugging support\n");	
#endif	
	}
}

int
subscript(var, attr_name, all, ret_var)
	Variable *var;
	char *attr_name;
	int all;
	Variable *ret_var;
{
	DICT_ATTR *dict;
	VALUE_PAIR *pair;

	ret_var->type = Undefined;
	if (var->type != Vector) {
		parse_error("subscript on non-vector");
		return -1;
	}
	if ((dict = attr_name_to_dict(attr_name)) == NULL) {
		parse_error("unknown attribute %s", attr_name);
		return -1;
	}
	
	pair = avl_find(var->datum.vector, dict->value);
	if (!pair) 
		return -1;

	switch (dict->type) {
	case TYPE_STRING:
		ret_var->type = String;
		if (all) {
			int length = 0;
			VALUE_PAIR *p;
			char *cp;
			
			/* First, count total length of all attribute
			   instances in the packet */
			for (p = pair; p; p = avl_find(p->next, dict->value)) 
				length += p->strlength;

			cp = ret_var->datum.string = alloc_string(length+1);
			/* Fill in the string contents */
			for (p = pair; p; p = avl_find(p->next, dict->value)) {
				memcpy(cp, p->strvalue, p->strlength);
				cp += p->strlength;
			}
			*cp = 0;
		} else
			ret_var->datum.string = dup_string(pair->strvalue);
		break;
	case TYPE_INTEGER:
	case TYPE_DATE:
		ret_var->type = Integer;
		ret_var->datum.number = pair->lvalue;
		break;
	case TYPE_IPADDR:
		ret_var->type = Ipaddress;
		ret_var->datum.ipaddr = pair->lvalue;
		break;
	default:
		radlog(L_CRIT,
		       _("attribute %s has unknown type"),
		       dict->name);
		exit(1);
	}
	return 0;
}


