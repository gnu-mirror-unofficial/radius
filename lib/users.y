%{
/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#include <sysdep.h>
#include <radius.h>
#include <parser.h>

#define YYMAXDEPTH 10

int old_lineno;

static void *closure;
static int (*add_entry)(void*, char *, int, char *, VALUE_PAIR *, VALUE_PAIR *);

static VALUE_PAIR *install_pair0(char *name, int op, char *valstr);
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
        MATCHING_RULE *rule;
        struct {
                VALUE_PAIR *lhs, *rhs;
        } descr;
        VALUE_PAIR *pair;
        int op;
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
                   users_sync(); yyerrok; yyclearin;
           }
         ;

entry    : user descr
           {
                   add_entry(closure,
                             source_filename,
                             old_lineno, $1, $2.lhs, $2.rhs);
           }
         | user error
           {
                   radlog(L_ERR, _("discarding user `%s'"), $1);
                   users_sync(); yyerrok; yyclearin;
           }   
         ;

user     : value
           {
                   old_lineno = source_line_num;
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
                                   avl_add_list(&$1, $3);
                           $$ = $1;
                   } else
                           $$ = $3;
           }
         ;

pair     : STRING op value
           {
                   $$ = install_pair0($1, $2, $3);   
           }
         | STRING op BOGUS
           {
                   YYERROR;
           }
         ;

op       : EQ
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

value    : STRING
         | QUOTE
         ;

%%

int
yyerror(char *s)
{
        radlog(L_ERR, "%s:%d: %s", source_filename, source_line_num, s);
}

VALUE_PAIR *
install_pair0(char *name, int op, char *valstr)
{
	return install_pair(source_filename, source_line_num, 
			    name, op, valstr);
}

VALUE_PAIR *
install_pair(char *file, int line, char *name, int op, char *valstr)
{
        DICT_ATTR       *attr = NULL;
        DICT_VALUE      *dval;
        VALUE_PAIR      *pair, *pair2;
        char *s;
        int x;
        time_t timeval;
        struct tm *tm, tms;
        
        if ((attr = attr_name_to_dict(name)) == (DICT_ATTR *)NULL) {
                radlog(L_ERR, _("%s:%d: unknown attribute `%s'"),
                       file, line, name);
                return NULL;
        }

        pair = avp_alloc();
        
        pair->next = NULL;
        pair->name = attr->name;
        pair->attribute = attr->value;
        pair->type = attr->type;
        pair->prop = attr->prop;
        pair->operator = op;

        if (valstr[0] == '=') {
                pair->eval = 1;
                pair->avp_strvalue = estrdup(valstr+1);
                pair->avp_strlength = strlen(pair->avp_strvalue);
                return pair;
        }

        pair->eval = 0;
        
        switch (pair->type) {
        case TYPE_STRING:
                if (pair->attribute == DA_EXEC_PROGRAM ||
                    pair->attribute == DA_EXEC_PROGRAM_WAIT) {
                        if (valstr[0] != '/' && valstr[0] != '|') {
                                radlog(L_ERR,
				     _("%s:%d: %s: not an absolute pathname"),
                                       file, line, name);
                                avp_free(pair);
                                return NULL;
                        }
                }

		pair->avp_strvalue = estrdup(valstr);
                pair->avp_strlength = strlen(pair->avp_strvalue);
		
		if (attr->parser && attr->parser(pair, &s)) {
			radlog(L_ERR, "%s:%d: %s %s: %s",
			       file, line,
			       _("attribute"),
			       pair->name, s);
			free(s);
			avp_free(pair);
			return NULL;
		}

                break;

        case TYPE_INTEGER:
                /*
                 *      For DA_NAS_PORT_ID, allow a
                 *      port range instead of just a port.
                 */
                if (attr->value == DA_NAS_PORT_ID) {
                        for (s = valstr; *s; s++)
                                if (!isdigit(*s))
                                        break;
                        if (*s) {
                                pair->type = TYPE_STRING;
                                pair->avp_strvalue = estrdup(valstr);
                                pair->avp_strlength = strlen(pair->avp_strvalue);
                                break;
                        }
                }
                if (isdigit(*valstr)) {
                        pair->avp_lvalue = atoi(valstr);
                } else if ((dval = value_name_to_value(valstr, pair->attribute)) == NULL) {
                        avp_free(pair);
                        radlog(L_ERR,
		       _("%s:%d: value %s is not declared for attribute %s"),
			       file, line, valstr, name);
                        return NULL;
                } else {
                        pair->avp_lvalue = dval->value;
                }
                break;

        case TYPE_IPADDR:
                if (pair->attribute != DA_FRAMED_IP_ADDRESS) {
                        pair->avp_lvalue = ip_gethostaddr(valstr);
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
                        pair->avp_lvalue = ip_gethostaddr(valstr);

                        /*
                         *      Add an extra (hidden) attribute.
                         */
                        pair2 = avp_alloc();
                        
                        pair2->name = "Add-Port-To-IP-Address";
                        pair2->attribute = DA_ADD_PORT_TO_IP_ADDRESS;
                        pair2->type = TYPE_INTEGER;
                        pair2->avp_lvalue = x;
                        pair2->next = pair;
                        pair = pair2;
                }
                break;
                
        case TYPE_DATE:
                timeval = time(0);
                tm = localtime_r(&timeval, &tms);
                if (user_gettime(valstr, tm)) {
                        radlog(L_ERR,
                                _("%s:%d: %s: can't parse date"),
                               file, line, name);
                        avp_free(pair);
                        return NULL;
                }
#ifdef TIMELOCAL
                pair->avp_lvalue = (UINT4)timelocal(tm);
#else /* TIMELOCAL */
                pair->avp_lvalue = (UINT4)mktime(tm);
#endif /* TIMELOCAL */
                break;

        default:
                radlog(L_ERR, _("%s:%d: %s: unknown attribute type %d"),
		       file, line, name, pair->type);
                avp_free(pair);
                return NULL;
        }

        return pair;
}

extern int yydebug;

int
parse_file(char *file, void *c, int (*f)())
{
        int rc;
        
        if (init_lex(file))
                return -1;
        closure = c;
        add_entry = f;

        yydebug = 0;
        rc = yyparse();
        done_lex();
        return rc;
}

void
enable_usr_dbg(int val)
{
        yydebug = val;
        if (yydebug)
                radlog(L_NOTICE, _("%s:%d: enabled userfile parser debugging"),
                       source_filename, source_line_num);
        else
                radlog(L_NOTICE, _("%s:%d: disabled userfile parser debugging"),
                       source_filename, source_line_num);
}
