/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
%{
	static char rcsid[] = 
	"$Id$";
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
        #include <radiusd.h>
        #include <parser.h>

        #define YYMAXDEPTH 10

	int old_lineno;

	static void *closure;
	static int (*add_entry)(void*, int, char *, VALUE_PAIR *, VALUE_PAIR *);

	VALUE_PAIR *install_pair(char *name, int op, char *valstr);
%}
%token EQ LT GT NE LE GE
%token NUL
%token <string> STRING QUOTE 
%type <string> user value
%type <descr> descr
%type <pair> npairlist pairlist pair
%type <pair_list> entry
%type <op> op

%start input

%union {
	char *string;
	PAIR_LIST *pair_list;
	struct {
		VALUE_PAIR *check, *reply;
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
		   add_entry(closure, old_lineno, $1, $2.check, $2.reply);
	   }
	 | user error
	   {
		   radlog(L_ERR, _("discarding user `%s'"), $1);
		   users_sync(); yyerrok; yyclearin;
    	   }   
         ;

user     : STRING
           {
		   old_lineno = source_line_num;
	   }
         ;

descr    : npairlist npairlist
           {
		   $$.check = $1;
		   $$.reply = $2;
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
				   pairlistadd(&$1, $3);
			   $$ = $1;
		   } else
			   $$ = $3;
	   }
         ;

pair     : STRING op value
           {
		   $$ = install_pair($1, $2, $3);   
	   }
         ;

op       : EQ
           {
		   $$ = PW_OPERATOR_EQUAL;
	   }
         | LT
           {
		   $$ = PW_OPERATOR_LESS_THAN;
	   }
         | GT
           { 
		   $$ = PW_OPERATOR_GREATER_THAN;
	   }
         | NE
           {
		   $$ = PW_OPERATOR_NOT_EQUAL;
	   }
         | LE
           {
		   $$ = PW_OPERATOR_LESS_EQUAL;
	   }
         | GE
           {
		   $$ = PW_OPERATOR_GREATER_EQUAL;
	   }
         ;

value    : STRING
         | QUOTE
         ;

%%

yyerror(s)
	char *s;
{
	radlog(L_ERR, "%s:%d: %s", source_filename, source_line_num, s);
}

VALUE_PAIR *
install_pair(name, op, valstr)
	char *name;
	int op;
	char *valstr;
{
	DICT_ATTR	*attr = NULL;
	DICT_VALUE	*dval;
	VALUE_PAIR	*pair, *pair2;
	char *s;
	int x;
	time_t timeval;
	struct tm *tm;
	
	if ((attr = dict_attrfind(name)) == (DICT_ATTR *)NULL) {
		radlog(L_ERR, _("%s:%d: unknown attribute `%s'"),
		       source_filename, source_line_num, name);
		return NULL;
	}

	pair = alloc_pair();
	
	pair->next = NULL;
	pair->name = attr->name;
	pair->attribute = attr->value;
	pair->type = attr->type;
	pair->operator = op;
	
	switch (pair->type) {
	case PW_TYPE_STRING:
		if (pair->attribute == DA_EXEC_PROGRAM ||
		    pair->attribute == DA_EXEC_PROGRAM_WAIT) {
			if (valstr[0] != '/') {
				radlog(L_ERR,
				   _("%s:%d: %s: not an absolute pathname"),
				       source_filename, source_line_num, name);
				free_pair(pair);
				return NULL;
			}
		}
		pair->strvalue = make_string(valstr);
		pair->strlength = strlen(pair->strvalue);
		break;

	case PW_TYPE_INTEGER:
		/*
		 *	For DA_NAS_PORT_ID, allow a
		 *	port range instead of just a port.
		 */
		if (attr->value == DA_NAS_PORT_ID) {
			for (s = valstr; *s; s++)
				if (!isdigit(*s))
					break;
			if (*s) {
				pair->type = PW_TYPE_STRING;
				pair->strvalue = make_string(valstr);
				pair->strlength = strlen(pair->strvalue);
				break;
			}
		}
		if (isdigit(*valstr)) {
			pair->lvalue = atoi(valstr);
		} else if ((dval = dict_valfind(valstr)) == NULL) {
			free_pair(pair);
			radlog(L_ERR|L_CONS, _("%s:%d: unknown value %s"),
			    source_filename, source_line_num,
			    valstr);
			return NULL;
		} else {
			pair->lvalue = dval->value;
		}
		break;

	case PW_TYPE_IPADDR:
		if (pair->attribute != DA_FRAMED_IP_ADDRESS) {
			pair->lvalue = get_ipaddr(valstr);
		} else {
			/*
			 *	We allow a "+" at the end to
			 *	indicate that we should add the
			 *	portno. to the IP address.
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
			pair->lvalue = get_ipaddr(valstr);

			/*
			 *	Add an extra (hidden) attribute.
			 */
			pair2 = alloc_pair();
			
			pair2->name = "Add-Port-To-IP-Address";
			pair2->attribute = DA_ADD_PORT_TO_IP_ADDRESS;
			pair2->type = PW_TYPE_INTEGER;
			pair2->lvalue = x;
			pair2->next = pair;
			pair = pair2;
		}
		break;
		
	case PW_TYPE_DATE:
		timeval = time(0);
		tm = localtime(&timeval);
		if (user_gettime(valstr, tm)) {
			radlog(L_ERR|L_CONS,
				_("%s:%d: %s: can't parse date"),
				source_filename, source_line_num, name);
			free_pair(pair);
			return NULL;
		}
#ifdef TIMELOCAL
		pair->lvalue = (UINT4)timelocal(tm);
#else /* TIMELOCAL */
		pair->lvalue = (UINT4)mktime(tm);
#endif /* TIMELOCAL */
		break;

	default:
		radlog(L_ERR|L_CONS, _("%s:%d: %s: unknown attribute type %d"),
		    source_filename, source_line_num, name,
		    pair->type);
		free_pair(pair);
		return NULL;
	}

	return pair;
}

extern int yydebug;

int
parse_file(file, c, f)
	char *file;
	void *c;
	int (*f)();
{
	int rc;
	
	if (init_lex(file))
		return -1;
	closure = c;
	add_entry = f;

#ifdef YACC_DEBUG
	yydebug = 0;
#endif
	rc = yyparse();
	done_lex();
	return rc;
}

void
enable_usr_dbg()
{
#ifdef YACC_DEBUG
	if (master_process()) {
		yydebug = 1;
		radlog(L_NOTICE, _("enabled userfile parser debugging"));
	}
#else
	radlog(L_WARN,
	    _("%s:%d: radiusd compiled without parser debugging"),
	    source_filename, source_line_num);
#endif
}









