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
%x STRING
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
	#include <radtest.h>
	#include "y.tab.h"

	int source_line_num;
	char *source_filename;
	static int interactive;

	static void add_str(char *str, int  len);
	static void add_chr(int c);
	static char *end_str();
	static void add_num(int skip, int base, char *text, int leng);

	static int backspace(int c);

	static void newline();
%}

WS [ \t][ \t]*
IDENTIFIER [a-zA-Z_\-][a-zA-Z_\-0-9.]*
D [0-9]+
D3 [0-9]{1,3}
DQ {D3}\.{D3}\.{D3}\.{D3}

%%
#.*\n   { /* a comment */
	newline();
	return EOL;
}	
#.*     /* end-of-file comment */;
auth    return AUTH;
acct    return ACCT;
cntl	return CNTL;
print   return PRINT;
all     return ALL;
vars    return VARS;
send    return SEND;
expect  return EXPECT;
{IDENTIFIER} {
	strncpy(yylval.string, yytext, sizeof(yylval.string));
	yylval.string[sizeof(yylval.string)-1] = 0;
	return NAME;
}
\${IDENTIFIER} {
	yylval.ident = (Variable*) sym_lookup(vartab, yytext+1);
	if (yylval.ident == NULL) {
		parse_error("variable %s used before definition", yytext+1);
		yylval.ident = (Variable*) sym_install(vartab, yytext+1);
		yylval.ident->type = Undefined;
	}
	return IDENT;
}
\"[^\\"]*\" {
        if (yyleng - 2 < sizeof(yylval.string)) { 
		strncpy(yylval.string, yytext+1, yyleng - 2);
		yylval.string[yyleng-2] = 0;
	} else {
		strncpy(yylval.string, yytext+1, sizeof(yylval.string));
		yylval.string[sizeof(yylval.string)-1] = 0;
	}
        return QUOTE;
}
\"[^\\"]*\\. {
	BEGIN(STRING);
        add_str(yytext+1, yyleng - 3);
        add_chr(backspace(yytext[yyleng-1]));
}
\"[^\\"]*\\[0-7]{1,3} {
	BEGIN(STRING);
        add_num(0, 8, yytext+1, yyleng-1);
}
\"[^\\"]*\\[xX][0-9a-fA-F]{1,2} {
	BEGIN(STRING);
        add_num(1, 16, yytext+1, yyleng-1);
}
<STRING>[^\\"]*\\[0-7]{1,3} {
	add_num(0, 8, yytext, yyleng);
}
<STRING>[^\\"]*\\[xX][0-9a-fA-F]{1,2} {
	add_num(1, 16, yytext, yyleng);
}
<STRING>[^\\"]*\\. {
	add_str(yytext, yyleng - 2);
	add_chr(backspace(yytext[yyleng-1]));
}
<STRING>[^\\"]*\" {
	BEGIN(INITIAL);
	add_str(yytext, yyleng - 1);
	strncpy(yylval.string, end_str(), sizeof(yylval.string));
	yylval.string[sizeof(yylval.string)-1] = 0;
	return QUOTE;
}
{DQ} {
	yylval.ipaddr = ipstr2long(yytext);
	return IPADDRESS;
}
{D} {
	yylval.number = atoi(yytext);
	return NUMBER;
}
{WS}    ;
\n      newline();
;       return EOL;
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

int
open_input(name)
	char *name;
{
	FILE *fp;

	if (name && strcmp(name, "-")) {
		source_filename = name;
		fp = fopen(name, "r");
		if (!fp) {
			radlog(L_ERR, "can't open input file `%s': %s",
			    name, strerror(errno));
			return 1;
		}
	} else {
		source_filename = "<teletype>";
		fp = stdin;
	}

	interactive = isatty(fileno(fp));
	source_line_num = 0;
	newline();
#ifdef FLEX_SCANNER
	yyrestart(fp);
#else
	yyin = fp;
#endif
	return 0;
}

void
close_input()
{
#ifdef FLEX_SCANNER	
	yy_delete_buffer(yy_current_buffer); 
#endif	
	fclose(yyin);
	yyin = NULL;
}


char prompt[] = "> ";

void
newline()
{
	source_line_num++;
	if (interactive) 
		printf("%s", prompt);
}

void
putback(str)
	char *str;
{
	char *p = str + strlen(str);

	while (--p > str)
		unput(*p);
}

void
add_num(skip, base, text, leng)
	int skip;
	int base;
	char *text;
	int leng;
{
        int n, d;

        n = 1;
        while (leng - n > 0 && text[leng - n] != '\\')
		n++;
	add_str(text, leng - n);
	n -= skip;
	add_chr(strtol(&text[leng - n + 1], NULL, base));
}

static char string_acc[MAX_STRING];
static char string_len;

void
add_str(str, len)
	char *str;
	int  len;
{
	if (string_len + len >= sizeof(string_acc)) 
		len = sizeof(string_acc) - string_len;
	if (len == 0)
		return;
	strncpy(string_acc + string_len, str, len);
	string_len += len;
}

void
add_chr(c)
	int c;
{
	if (string_len + 1 >= sizeof(string_acc)) 
		return;
	string_acc[string_len++] = c;
}

char *
end_str()
{
	string_acc[string_len] = 0;
	string_len = 0;
	return string_acc;
}

int
backspace(c)
	int c;
{
	switch (c) {
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
	}
	return c;
}
