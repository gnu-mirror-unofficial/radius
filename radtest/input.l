%x STRING HEREDOC
%{
/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

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

#include <common.h>
#include <radius/radius.h>	
#include <radtest.h>
#include "gram.h"

#if !HAVE_DECL_GETLINE
int getline (char **lineptr, size_t *n, FILE *stream);
#endif

int interactive;                   /* Are we in interactive mode? */
char prompt_str[] = "radtest> ";   /* Prompt string for interactive mode */
grad_locus_t source_locus;         /* Current location in the source file */
static struct obstack string_stk;  /* Keeps all string literals. Gets freed
				      after compilation and (eventual)
				      execution of the statement */

size_t string_start_line;          /* In STRING and HEREDOC mode keeps
				      the line where the string definition
				      has started */

/* Here document support */ 
static char *heredoc_delimiter;    /* End delimiter for here document */ 
static int strip_tabs;             /* Strip leading tab characters */
 

/* Input buffer */

/* The variables below are used only in interactive mode */ 
static char *input_line;           /* Input line */
static size_t input_length;        /* Size of input_line */
static size_t input_pos;           /* Current position in input_line */

/* Read from the input stream at most `bufsize' character into buffer `buf' */
static int
fill_input_buffer(char *buf, int bufsize)
{
	if (interactive) {
		int rest;
		
		if (!input_line || input_pos == input_length) {
			if (disable_readline) {
				static size_t input_size;
				
				printf("%s", prompt_str);
				fflush(stdout);
				
				if (getline(&input_line, &input_size,
					    yyin) < 0) {
					free (input_line);
					input_line = NULL;
					input_length = 0;
					return 0;
				}
				input_length = strlen(input_line);
				input_pos = 0;
			} else {
				free(input_line);
				input_line = grad_readline(prompt_str);
				if (!input_line)
					return 0;
				grad_add_history(input_line);
				input_length = strlen (input_line);
				input_line = realloc(input_line,
						     input_length+2);
				if (!input_line) {
					fprintf (stderr,
						 _("low core: aborting"));
					abort();
				}
				input_line[input_length++] = '\n';
				input_line[input_length] = 0;
				input_pos = 0;
			}
		}
		rest = input_length - input_pos;
		if (bufsize > rest)
			bufsize = rest;
		memcpy(buf, input_line + input_pos, bufsize);
		input_pos += bufsize;
		return bufsize;
	} else {
		return fread(buf, 1, bufsize, yyin);
	}
}
			
#ifdef FLEX_SCANNER
/* Input support for flex */
 
#undef YY_INPUT
#define YY_INPUT(buf,result,max_size) \
  result = fill_input_buffer(buf, max_size)

#else /* !FLEX_SCANNER */
/* Input processing for AT&T Lex. Untested. */

static int
xinput()
{
	char c;
	if (fill_input_buffer(&c, 1) <= 0)
		return EOF;
	return c;
}

static int
xunput(int c)
{
	if (input_pos == 0) 
		abort();
	return input_line[--input_pos] = c;
}
 
#undef unput
#define unput(c) xunput(c)
#undef input
#define input() xinput()

#endif /* FLEX_SCANNER */ 

static size_t string_len;
static int binary_string;

/* Forward declarations */
static void begin_str();
static void add_str(char *str, int  len);
static void add_chr(int c);
static char *end_str();
static void add_num(int skip, int base, char *text, int leng);

static int backspace(int c);

static int isemptystr(char *text);
static char *heredoc_strip_tabs(char *text);
static void heredoc_begin();

%}

WS [ \t][ \t]*
IDENTIFIER [a-zA-Z_][a-zA-Z_0-9\.-]*
D [0-9]+
D3 [0-9]{1,3}
DQ {D3}\.{D3}\.{D3}\.{D3}

%%
#.*\n   { /* a comment */
        source_locus.line++;
        return EOL;
}       
#.*     /* end-of-file comment */;
'[^']*' {
	add_str(yytext+1,yyleng-2);
        yylval.string = end_str();
        return NAME;
}
auth    return AUTH;
acct    return ACCT;
print   return PRINT;
send    return SEND;
expect  return EXPECT;
exit    return EXIT;
begin   return T_BEGIN; 
end     return T_END;
if      return IF;
else    {
	switch (peek_ctx()) {
	case ctx_if:
	          return ELSE;

	case ctx_iferr:
		pop_ctx();
		break;

	default:
		  parse_error(_("Misplaced 'else'"));
		  /* Skip the token */
	}
} 
while   {
	if (peek_ctx() == ctx_doerr) 
		pop_ctx();
	else
		return WHILE;
}
do      return DO;
break   return BREAK;
continue return CONTINUE;
not     return NOT;
or      return OR;
and     return AND;
input   return INPUT;
shift   return SHIFT;
getopt  return GETOPT;
case    return CASE;
in      return IN;
return  return T_RETURN;
set{WS}.*\n {
	int i, argc;
	char **argv;
	char *p;
	
	grad_argcv_get(yytext, "", NULL, &argc, &argv);
	for (i = 0; i < argc; i++) 
		add_str(argv[i], strlen(argv[i])+1);

	add_chr(0);
	for (p = end_str(); *p; p += strlen(p) + 1)
		obstack_ptr_grow(&string_stk, p);
	p = NULL;
	obstack_ptr_grow(&string_stk, p);
	yylval.set.argc = argc;
	yylval.set.argv = obstack_finish(&string_stk);
	grad_argcv_free(argc, argv);
	if (yytext[yyleng-2] == '\\')
		yyless(yyleng-2);
	else
		yyless(yyleng-1);
	return SET;
}
{IDENTIFIER} {
	int n = grad_request_name_to_code(yytext);
	if (n != 0) {
		yylval.number = n;
		return NUMBER;
	}
	add_str(yytext,yyleng);
        yylval.string = end_str();
        return NAME;
}
\${IDENTIFIER}- {
	add_str(yytext+1,yyleng-2);
	yylval.deref.name = end_str();
	yylval.deref.repl = NULL;
	yyless(yyleng-1);
	return IDENT;
}
\${IDENTIFIER} {
	add_str(yytext+1,yyleng-1);
	yylval.deref.name = end_str();
	yylval.deref.repl = NULL;
	return IDENT;
}
\$\{{IDENTIFIER}\}- {
	add_str(yytext+2, yyleng-4);
        yylval.deref.name = end_str();
	yylval.deref.repl = NULL;
	yyless(yyleng-1);
        return IDENT;
}
\$\{{IDENTIFIER}\} {
	add_str(yytext+2, yyleng-3);
        yylval.deref.name = end_str();
	yylval.deref.repl = NULL;
        return IDENT;
}
\$\{{IDENTIFIER}:[=:?\-&].*\}- {
	char *p;
	add_str(yytext+2, yyleng-4);
        yylval.deref.name = end_str();
	p = strchr(yylval.deref.name, ':');
	*p++ = 0;
	yylval.deref.repl = p;
	yyless(yyleng-1);
        return IDENT;
}
\$\{{IDENTIFIER}:[=:?\-&].*\} {
	char *p;
	add_str(yytext+2, yyleng-3);
        yylval.deref.name = end_str();
	p = strchr(yylval.deref.name, ':');
	*p++ = 0;
	yylval.deref.repl = p;
        return IDENT;
}
\$# 	return ARGCOUNT;
\${D}  {
	yylval.parm.number = strtoul(yytext+1, NULL, 0);
	yylval.parm.repl = NULL;
	return PARM;
}
\$\{{D}\} {
	yylval.parm.number = strtoul(yytext+2, NULL, 0);
	yylval.parm.repl = NULL;
	return PARM;
}
\$\{{D}:[=:?\-&].*\} {
	char *p;
	yylval.parm.number = strtoul(yytext+2, &p, 0);
	p++;
	add_str(p, strlen(p)-1);
	yylval.parm.repl = end_str();
	return PARM;
}
\"[^\\"]*\" {
        begin_str();
        add_str(yytext+1, yyleng-2);
        yylval.string = end_str();
        return QUOTE;
}
\"[^\\"]*\n {
        BEGIN(STRING);
        begin_str();
	string_start_line = source_locus.line++;
        add_str(yytext+1, yyleng-1);
}
\"[^\\"]*\\. {
        BEGIN(STRING);
        begin_str();
        string_start_line = source_locus.line;
        if (yytext[yyleng-1] == '\n')
                source_locus.line++;
        add_str(yytext+1, yyleng - 3);
        add_chr(backspace(yytext[yyleng-1]));
}
\"[^\\"]*\\[0-7]{1,3} {
        BEGIN(STRING);
        begin_str();
        add_num(0, 8, yytext+1, yyleng-1);
}
\"[^\\"]*\\[xX][0-9a-fA-F]{1,2} {
        BEGIN(STRING);
        begin_str();
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
                source_locus.line++;
        add_str(yytext, yyleng - 2);
        add_chr(backspace(yytext[yyleng-1]));
}
<STRING>[^\\"]*\n {
        source_locus.line++;
        add_str(yytext, yyleng);
        add_chr(backspace(yytext[yyleng-1]));
}
<STRING>[^\\"]*\" {
        BEGIN(INITIAL);
        add_str(yytext, yyleng - 1);
        if (binary_string) {
            yylval.bstring.ptr = end_str();
            yylval.bstring.length = string_len;
            return BSTRING;
        } else {
            yylval.string = end_str();
            return QUOTE;
        }
}
"<<"-?{IDENTIFIER}.*\n {
	BEGIN(HEREDOC);
        begin_str();
	string_start_line = source_locus.line++;
	heredoc_begin();
}
<HEREDOC>.*\n {
	char *p = heredoc_strip_tabs (yytext);
	if (strncmp (p, heredoc_delimiter, strlen (heredoc_delimiter))
	    == 0
	    && isemptystr (p + strlen (heredoc_delimiter))) {
		grad_free (heredoc_delimiter);
		heredoc_delimiter = NULL;
		BEGIN(INITIAL);
		yylval.string = end_str();
		yyless(yyleng-1);
		return QUOTE;
	}
	add_str(p, strlen(p));
        source_locus.line++;
}
{DQ} {
        yylval.ipaddr = grad_ip_strtoip(yytext);
        return IPADDRESS;
}
{D} {
        yylval.number = strtol(yytext, NULL, 0);
        return NUMBER;
}
{WS}    ;
\\\n    source_locus.line++;
\n      { source_locus.line++; return EOL; }
;       return EOL;
"="     return EQ;
"!="    return NE;
">"     return GT;
"<"     return LT;
">="    return GE;
"<="    return LE;
"!"     return NOT;
.       return yytext[0];

%%

int
yywrap()
{
	if (YYSTATE == STRING) 
		parse_error(_("Unexpected end of file in string started on line %lu"),
			    string_start_line);
	else if (YYSTATE == HEREDOC)
		parse_error(_("Unexpected end of file in multiline string started on line %lu"),
			    string_start_line);
		
	grad_write_history_file();
        return 1;
}

int
open_input(char *name)
{
        FILE *fp;

        obstack_init(&string_stk);
        if (name && strcmp(name, "-")) {
                source_locus.file = name;
                fp = fopen(name, "r");
                if (!fp) {
                        grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
                                 _("can't open input file `%s'"), name);
                        return 1;
                }
        } else {
                source_locus.file = "<teletype>";
                fp = stdin;
        }

	interactive = isatty(fileno(fp));
	grad_readline_init("radtest", interactive, radtest_command_completion);
	if (interactive) 
		grad_readline_set_input(fp);
	grad_read_history_file();

        source_locus.line = 1;
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
        yy_delete_buffer(YY_CURRENT_BUFFER); 
#endif  
        fclose(yyin);
        yyin = NULL;
        obstack_free(&string_stk, NULL);
}


/* String processing functions */

/* Read string segment ending with a numeric escape (\0.. or \x),
   and append it to the current string object.
   Arguments:
     skip     Number of characters to skip when processing the escape:
              0 for octal escapes, 1 -- for hex ones.
     base     Conversion base for the escape.
     text     Start of the string segment.
     leng     Length of the string segment. */
void
add_num(int skip, int base, char *text, int leng)
{
        int n;

        n = 1;
        while (leng - n > 0 && text[leng - n] != '\\')
                n++;
        add_str(text, leng - n);
        n -= skip;
        add_chr(strtol(&text[leng - n + 1], NULL, base));
}

void
begin_str()
{
	string_len = 0;
	binary_string = 0;
}

/* Append simple string segment to the current string object */
void
add_str(char *str, int len)
{
        obstack_grow(&string_stk, str, len);
        string_len += len;
}

/* Append a single character */
void
add_chr(int c)
{
        obstack_1grow(&string_stk, c);
        string_len++;
	if (c == 0)
		binary_string++;
}

/* Finish the string being constructed. Return pointer to its beginning. */
char *
end_str()
{
	obstack_1grow(&string_stk, 0);
        return obstack_finish(&string_stk);
}

/* Translate a second part of a C escape */
int
backspace(int c)
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

/* External interfaces to the above functions */
void
radtest_start_string(char *str)
{
	/* FIXME: Make sure no leading garbage appears */
	add_str(str, strlen(str));
}

void
radtest_add_string(char *str)
{
	add_str(str, strlen(str));
}

char *
radtest_end_string()
{
	return end_str();
}

/* Free all string literals */
void
radtest_free_strings()
{
	obstack_free(&string_stk, NULL);
	obstack_init(&string_stk);
}

/* This function is called when we have to remember all collected
   string literals (e.g. for a function definition).
   Current implementation simply re-initializes string stack. A
   (possibly) better approach:
   use some start_ptr and do obstack_free(&string_stk, start_ptr) in
   radtest_free_strings(). Then it should suffice to do

   obstack_1grow(&string_stk, 0);
   start_ptr = obstack_finish(&string_stk)

   here. */

void
radtest_fix_strings()
{
	obstack_init(&string_stk);
}


/* "Here document" support */

/* Return 1 if `text' is an empty string */
static int
isemptystr(char *text)
{
	for (; *text && isspace (*text); text++)
		;
	return *text == 0;
}

/* Strip initial tab characters from `text' */
static char *
heredoc_strip_tabs(char *text)
{
	if (strip_tabs)
		for (; *text == '\t'; text++)
			;
	return text;
}

/* Begin processing of a "here document" construct */
static void
heredoc_begin()
{
	char *p = yytext + 2; /* past the << marker */

	if (*p == '-') {
		strip_tabs = 1;
		p++;
	}
	else
		strip_tabs = 0;

	if (!isspace (*p)) {
		char *endp;
		int len;
      
		for (endp = p; *endp; endp++)
			if (isspace (*endp))
				break;

		len = endp - p;
		heredoc_delimiter = grad_emalloc(len + 1);
		memcpy(heredoc_delimiter, p, len);
		heredoc_delimiter[len] = 0;
	} else {
		heredoc_delimiter = grad_estrdup (".");
	}
}

/* End of input.l */
