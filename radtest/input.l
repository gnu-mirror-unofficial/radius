%x STRING
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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */
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

#include <radius.h>
#include <obstack1.h> 
#include <radtest.h>
#include "gram.h"

#if !HAVE_DECL_GETLINE
int getline (char **lineptr, size_t *n, FILE *stream);
#endif

int source_line_num;
char *source_filename;
static int interactive;
static struct obstack string_stk;
 
static void add_str(char *str, int  len);
static void add_chr(int c);
static char *end_str();
static void add_num(int skip, int base, char *text, int leng);

static int backspace(int c);
static int deref_var(char *name, char *p);
static int deref_parm(unsigned num, char *p);
%}

WS [ \t][ \t]*
IDENTIFIER [a-zA-Z_\-][a-zA-Z_\-0-9.]*
D [0-9]+
D3 [0-9]{1,3}
DQ {D3}\.{D3}\.{D3}\.{D3}

%%
#.*\n   { /* a comment */
        source_line_num++;
        return EOL;
}       
#.*     /* end-of-file comment */;
auth    return AUTH;
acct    return ACCT;
print   return PRINT;
all     return ALL;
vars    return VARS;
send    return SEND;
expect  return EXPECT;
exit    return EXIT;
{IDENTIFIER} {
        yylval.string = string_create(yytext);
        return NAME;
}
\${IDENTIFIER} return deref_var(yytext+1, NULL);
\$\{{IDENTIFIER}\} {
        int type;
        char *name = estrdup(yytext+2);
        name[yyleng-3] = 0;
        type = deref_var(yytext+2, NULL);
        efree(name);
        return type;
}
\$\{{IDENTIFIER}:[=:?\-&].*\} {
        char *name, *p;
        int type;
        
        name = estrdup(yytext+2);
        name[yyleng-3] = 0;
        p = strchr(name, ':');
        *p++ = 0;
        type = deref_var(name, p);
        efree(name);
        return type;
}
\${D}  return deref_parm(strtoul(yytext+1, NULL, 0), NULL);
\$\{{D}\} return deref_parm(strtoul(yytext+2, NULL, 0), NULL);
\$\{{D}:[=:?\-&].*\} {
        char *name, *p;
        int type;
        
        name = estrdup(yytext+2);
        name[yyleng-3] = 0;
        p = strchr(name, ':');
        *p++ = 0;
        type = deref_parm(strtoul(name, NULL, 0), p);
        efree(name);
        return type;
}
\"[^\\"]*\" {
        yylval.string = string_alloc(yyleng - 1);
        memcpy(yylval.string, yytext+1, yyleng - 2);
        yylval.string[yyleng-2] = 0;
        return QUOTE;
}
\"[^\\"]*\n {
        BEGIN(STRING);
        source_line_num++;
        add_str(yytext+1, yyleng-1);
}
\"[^\\"]*\\. {
        BEGIN(STRING);
        if (yytext[yyleng-1] == '\n')
                source_line_num++;
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
        if (yytext[yyleng-1] == '\n')
                source_line_num++;
        add_str(yytext, yyleng - 2);
        add_chr(backspace(yytext[yyleng-1]));
}
<STRING>[^\\"]*\n {
        source_line_num++;
        add_str(yytext, yyleng);
        add_chr(backspace(yytext[yyleng-1]));
}
<STRING>[^\\"]*\" {
        BEGIN(INITIAL);
        add_str(yytext, yyleng - 1);
        yylval.string = string_create(end_str());
        return QUOTE;
}
{DQ} {
        yylval.ipaddr = ip_strtoip(yytext);
        return IPADDRESS;
}
{D} {
        yylval.number = atoi(yytext);
        return NUMBER;
}
{WS}    ;
\\\n    source_line_num++;
\n      { source_line_num++; return EOL; }
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

        obstack_init(&string_stk);
        if (name && strcmp(name, "-")) {
                source_filename = name;
                fp = fopen(name, "r");
                if (!fp) {
                        radlog(L_ERR|L_PERROR,
                               _("can't open input file `%s'"), name);
                        return 1;
                }
        } else {
                source_filename = "<teletype>";
                fp = stdin;
        }

        interactive = isatty(fileno(fp));
        source_line_num = 0;
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
        obstack_free(&string_stk, NULL);
}


char prompt_str[] = "radtest> ";

void
prompt()
{
        if (interactive) 
                printf("%s", prompt_str);
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
        int n;

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
        obstack_grow(&string_stk, str, len);
        string_len += len;
}

void
add_chr(c)
        int c;
{
        obstack_1grow(&string_stk, c);
        string_len++;
}

char *
end_str()
{
        return obstack_finish(&string_stk);
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

int
deref_var(name, p)
        char *name, *p;
{
        int type;
        union datum datum;
        size_t n;
        
        yylval.ident = (Variable*) sym_lookup(vartab, name);
        if (yylval.ident) 
                return IDENT;
        else if (!p) {
                parse_error("variable %s used before definition", name);
                yylval.ident = sym_install(vartab, name);
                yylval.ident->type = Undefined;
                return IDENT;
        }

        switch (*p++) {
        case '=':
                yylval.ident = (Variable*) sym_install(vartab, name);
                yylval.ident->type = parse_datum(p, &yylval.ident->datum);
                type = IDENT;
                break;
                
        case '-':
                switch (parse_datum(p, &datum)) {
                case Undefined:
                        parse_error("variable %s used before definition", name);
                        yylval.ident = sym_install(vartab, name);
                        yylval.ident->type = Undefined;
                        type = IDENT;
                        break;
                        
                case Integer:
                        yylval.number = datum.number;
                        type = NUMBER;
                        break;
                        
                case Ipaddress:
                        yylval.ipaddr = datum.ipaddr;
                        type = IPADDRESS;
                        break;
                        
                case String:
                        yylval.string = datum.string;
                        type = QUOTE;
                        break;
                        
                default:
                        radlog(L_CRIT,
                               "%s:%d: FATAL ERROR",
                               __FILE__, __LINE__);
                        abort();
                }
                break;
                
        case '?':
                if (*p) 
                        fprintf(stderr, "%s\n", p);
                else
                        fprintf(stderr, "%s: variable unset\n", name);
                exit(1);
                                
        case ':':
                if (*p)
                        printf("%s", p);
                else
                        printf("(%s:%d)%s? ",
                               source_filename,
                               source_line_num,
                               name);
                p = NULL;
                n = 0;
                getline(&p, &n, stdin);
                yylval.string = string_create(p);
                free(p);
                type = QUOTE;
                break;
                
        case '&':
                if (!*p)
                        asprintf(&p, "(%s:%d)%s? ",
                                 source_filename,
                                 source_line_num,
                                 name);
                p = getpass(p);
                if (!p)
                        exit(0);
                yylval.string = string_create(p);
                type = QUOTE;
                break;
        }
        
        return type;
}

int
deref_parm(num, p)
        unsigned num;
        char *p;
{
        size_t n;
        
        if (num < x_argc && x_argv[num]) {
                yylval.string = string_create(x_argv[num]);
                return QUOTE;
        }
        
        if (!p) {
                yylval.string = string_create("");
                return QUOTE;
        }
        
        switch (*p++) {
        case '=':
                if (num > x_argmax) {
                        x_argmax = num;
                        x_argv = erealloc(x_argv, sizeof(x_argv[0])*(num+1));
                }
                x_argv[num] = string_create(p);
                x_argc = num+1;
                yylval.string = x_argv[num];
                break;
                
        case '-':
                yylval.string = string_create(p);
                break;
                
        case '?':
                if (*p) 
                        fprintf(stderr, "%s\n", p);
                else
                        fprintf(stderr, "parameter %d unset\n", num);
                exit(1);
                                
        case ':':
                if (*p)
                        printf("%s", p);
                else
                        printf("(%s:%d)%d? ",
                               source_filename,
                               source_line_num,
                               num);
                p = NULL;
                n = 0;
                getline(&p, &n, stdin);
                yylval.string = string_create(p);
                free(p);
                break;
                
        case '&':
                if (!*p)
                        asprintf(&p, "(%s:%d)%d? ",
                                 source_filename,
                                 source_line_num,
                                 num);
                p = getpass(p);
                if (!p)
                        exit(0);
                yylval.string = string_create(p);
                break;
        }
        return QUOTE;
}
