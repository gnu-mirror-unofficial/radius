%{
/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007,
   2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

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

#include <radlib.h>
#include "intprops.h"
	
#define YYMAXDEPTH 10

static grad_locus_t start_loc;

static void *closure;
static register_rule_fp add_entry;
static grad_avp_t *grad_create_pair0(char *name, int op, char *valstr);

int yyerror(char *s);
extern int yylex();
 
%}
%token EQ LT GT NE LE GE
%token NUL
%token BOGUS
%token <string> STRING QUOTE  
%type <string> user value
%type <descr> descr
%type <pair> npairlist pairlist pair
%type <rule> entry
%type <op> op

%start input

%union {
        char *string;
        grad_matching_rule_t *rule;
        struct {
                grad_avp_t *lhs, *rhs;
        } descr;
        grad_avp_t *pair;
        enum grad_operator op;
} 

%%

input    : /* empty */
         | list
         ;

list     : entry
           {
           } 
         | list entry
         | list error
           {
                   grad_parser_lex_sync(); yyerrok; yyclearin;
           }
         ;

entry    : user descr
           {
                   add_entry(closure, &start_loc, $1, $2.lhs, $2.rhs);
           }
         | user error
           {
                   grad_log(GRAD_LOG_ERR, _("discarding user `%s'"), $1);
                   if (grad_parser_lex_sync() <= 0)
			   yychar = 0; /* force end-of-file */
		   else {
			   yyerrok;
			   yyclearin;
		   }
           }   
         ;

user     : value
           {
		   start_loc = grad_parser_source_locus;
           }
         ;

descr    : npairlist npairlist
           {
                   $$.lhs = $1;
                   $$.rhs = $2;
           }
         ;

npairlist: NUL
           {
                   $$ = NULL;
           }
         | pairlist
         ;

pairlist : pair
         | pairlist ',' pair
           {
                   if ($1) {
                           if ($3) 
                                   grad_avl_add_list(&$1, $3);
                           $$ = $1;
                   } else
                           $$ = $3;
           }
         ;

pair     : STRING op value
           {
                   $$ = grad_create_pair0($1, $2, $3);   
           }
         | STRING op BOGUS
           {
                   YYERROR;
           }
         ;

op       : EQ
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

value    : STRING
         | QUOTE
         ;

%%

int
yyerror(char *s)
{
	grad_log_loc(GRAD_LOG_ERR, &grad_parser_source_locus, "%s", s);
	return 0;
}

grad_avp_t *
grad_create_pair0(char *name, int op, char *valstr)
{
	return grad_create_pair(&grad_parser_source_locus, name, op, valstr);
}

grad_avp_t *
grad_create_pair(grad_locus_t *loc, char *name, 
                 enum grad_operator op, char *valstr)
{
        grad_dict_attr_t *attr = NULL;
        grad_dict_value_t *dval;
        grad_avp_t *pair, *pair2;
        char *s;
        int x;
        time_t timeval;
        struct tm *tm, tms;
        
        if ((attr = grad_attr_name_to_dict(name)) == NULL) {
                grad_log_loc(GRAD_LOG_ERR, loc, _("unknown attribute `%s'"),
			     name);
                return NULL;
        }

        pair = grad_avp_alloc();
        
        pair->next = NULL;
        pair->name = attr->name;
        pair->attribute = attr->value;
        pair->type = attr->type;
        pair->prop = attr->prop;
        pair->operator = op;

        if (valstr[0] == '=') {
                pair->eval_type = grad_eval_interpret;
                pair->avp_strvalue = grad_estrdup(valstr+1);
                pair->avp_strlength = strlen(pair->avp_strvalue);
                return pair;
        }

        pair->eval_type = grad_eval_const;
        
        switch (pair->type) {
        case GRAD_TYPE_STRING:
                if (pair->attribute == DA_EXEC_PROGRAM ||
                    pair->attribute == DA_EXEC_PROGRAM_WAIT) {
                        if (valstr[0] != '/' && valstr[0] != '|') {
                                grad_log_loc(GRAD_LOG_ERR, loc,
					     _("%s: not an absolute pathname"),
					     name);
                                grad_avp_free(pair);
                                return NULL;
                        }
                }

		pair->avp_strvalue = grad_estrdup(valstr);
                pair->avp_strlength = strlen(pair->avp_strvalue);
		
		if (attr->parser && attr->parser(pair, &s)) {
			grad_log_loc(GRAD_LOG_ERR, loc,
				     "%s %s: %s",
				     _("attribute"),
				     pair->name, s);
			free(s);
			grad_avp_free(pair);
			return NULL;
		}

                break;

        case GRAD_TYPE_INTEGER:
                /*
                 *      For DA_NAS_PORT_ID, allow a
                 *      port range instead of just a port.
                 */
                if (attr->value == DA_NAS_PORT_ID) {
                        for (s = valstr; *s; s++)
                                if (!isdigit(*s))
                                        break;
                        if (*s) {
                                pair->type = GRAD_TYPE_STRING;
                                pair->avp_strvalue = grad_estrdup(valstr);
                                pair->avp_strlength = strlen(pair->avp_strvalue);
                                break;
                        }
                }
                if (isdigit(*valstr)) {
                        pair->avp_lvalue = atoi(valstr);
                } else if ((dval = grad_value_name_to_value(valstr,
							    pair->attribute))
			         == NULL) {
                        grad_avp_free(pair);
                        grad_log_loc(GRAD_LOG_ERR, loc,
				_("value %s is not declared for attribute %s"),
				     valstr, name);
                        return NULL;
                } else {
                        pair->avp_lvalue = dval->value;
                }
                break;

        case GRAD_TYPE_IPADDR:
                if (pair->attribute != DA_FRAMED_IP_ADDRESS) {
                        pair->avp_lvalue = grad_ip_gethostaddr(valstr);
                } else {
                        /*
                         *      We allow a "+" at the end to
                         *      indicate that we should add the
                         *      portno. to the IP address.
                         */
                        x = 0;
                        if (valstr[0]) {
                                for(s = valstr; s[1]; s++)
                                        ;
                                if (*s == '+') {
                                        *s = 0;
                                        x = 1;
                                }
                        }
                        pair->avp_lvalue = grad_ip_gethostaddr(valstr);

			if (x) {
				char *s;
				char buf[INT_BUFSIZE_BOUND(long)];
				grad_longtostr(pair->avp_lvalue,
					       buf, sizeof buf);
				grad_astrcat(&s, buf, "+", "%{NAS-Port-Id}",
					     NULL);
				pair->avp_strvalue = grad_estrdup(s);
				pair->avp_strlength = strlen(pair->avp_strvalue);
				pair->eval_type = grad_eval_interpret;
				free(s);
			}
                }
                break;
                
        case GRAD_TYPE_DATE:
                timeval = time(0);
                tm = localtime_r(&timeval, &tms);
                if (grad_parse_time_string(valstr, tm)) {
                        grad_log_loc(GRAD_LOG_ERR, loc, _("%s: can't parse date"),
				     name);
                        grad_avp_free(pair);
                        return NULL;
                }
#ifdef TIMELOCAL
                pair->avp_lvalue = (grad_uint32_t)timelocal(tm);
#else /* TIMELOCAL */
                pair->avp_lvalue = (grad_uint32_t)mktime(tm);
#endif /* TIMELOCAL */
                break;

        default:
                grad_log_loc(GRAD_LOG_ERR, loc,
			     _("%s: unknown attribute type %d"),
			     name, pair->type);
                grad_avp_free(pair);
                return NULL;
        }

        return pair;
}

extern int yydebug;

int
grad_parse_rule_file(char *file, void *c, register_rule_fp f)
{
        int rc;
        
        if (grad_parser_lex_init(file))
                return -1;
        closure = c;
        add_entry = f;

        yydebug = 0;
        rc = yyparse();
        grad_parser_lex_finish();
        return rc;
}

void
grad_enable_rule_debug(int val)
{
        yydebug = val;
	grad_log_loc(GRAD_LOG_NOTICE, &grad_parser_source_locus,
		     yydebug ? _("enabled userfile parser debugging") :
             	 	       _("disabled userfile parser debugging"));
}
