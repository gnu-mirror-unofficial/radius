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
/* $Id$ */
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
        #include <time.h>
        #include <ctype.h>
        #include <unistd.h>
        #include <signal.h>
        #include <errno.h>
        #include <sys/wait.h>

        #include <radiusd.h>

        #include <obstack1.h>
        #include <parser.h>
	#include "users_gram.h"

	extern void enable_usr_dbg();
	char *addstring();
	char *addquote();
	struct obstack stack;

	int source_line_num;
	char *source_filename;
%}

WS [ \t][ \t]*
IDENT [a-zA-Z_\-0-9.]+
%%
#.*\n   {
	  if (strncmp(yytext+1, "debug", 5) == 0)
		  enable_usr_dbg();
	  source_line_num++; /* a comment */
        }
#.*     /* end-of-file comment */;
NULL    return NUL;
{IDENT} {
	  yylval.string = addstring(yytext);
	  return STRING;
        }
\"[^"]*\" {
          yylval.string = addquote(yytext);
          return QUOTE;
        }
{WS}    ;
\n      {
          source_line_num++;
        }
"="     return EQ;
"!="    return NE;
">"     return GT;
"<"     return LT;
">="    return GE;
"<="    return LE;
.       return yytext[0];

%%

int
yywrap()
{
	return 1;
}

char *
addstring(s)
        char *s;
{
	int length = strlen(s);
	obstack_grow(&stack, s, length+1);
	return obstack_finish(&stack);
}
	
char *
addquote(s)
        char *s;
{
	int length = strlen(s);
	if (length-2 > 0)
		obstack_grow(&stack, s+1, length-2);
	obstack_1grow(&stack, 0);
	return obstack_finish(&stack);
}

int
init_lex(name)
	char *name;
{
	FILE *fp;

	source_filename = name;
	source_line_num = 1;
	obstack_init(&stack);
	fp = fopen(name, "r");
	if (!fp) {
		radlog(L_ERR|L_PERROR, _("can't open `%s'"),  name);
		return 1;
	}
#ifdef FLEX_SCANNER
	yyrestart(fp);
#else
	yyin = fp;
#endif
	return 0;
}

int
init_lex_f(fp)
	FILE *fp;
{

	source_filename = "<file>";
	source_line_num = 1;
	obstack_init(&stack);
#ifdef FLEX_SCANNER
	yyrestart(fp);
#else
	yyin = fp;
#endif
	return 0;
}

void
done_lex()
{
	obstack_free(&stack, NULL);
#ifdef FLEX_SCANNER	
	yy_delete_buffer(yy_current_buffer); 
#endif	
	fclose(yyin);
	yyin = NULL;
}

/* A rudimentary attempt to syncronize input after an error.
 * It is based on the assumption that only user names start
 * at column 0
 */
void
users_sync()
{
	int c;
	while ((c = input()) > 0) {
		if (c == '\n') {
			do {
				c = input();
			} while (c == '\n');
			if (!isspace(c)) {
				if (c)
					unput(c);
				return;
			} 
		}
	}
}
