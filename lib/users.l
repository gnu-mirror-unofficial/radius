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
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */
%e 8000
%p 15000
%x in_string
%{
 
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

#include <radlib.h>
#include <users_gram.h>

extern void grad_enable_rule_debug(int);
extern int yyerror(char *s); 
static char *addstring();
static char *addquote();
static int preproc();
static void read_number(char *text, int len, int base);
static void grow_backslash_num(grad_slist_t slist, char *text, int len,
			       int base);

static grad_slist_t slist;   /* Slist for keeping string values */ 
grad_locus_t grad_parser_source_locus;
ino_t source_inode;          /* Inode of the current source (for preventing
                                recursive inclusion */

        
#ifdef FLEX_SCANNER
#define xinput() (yyin ? getc(yyin) : EOF)
#undef YY_INPUT
#define YY_INPUT(buf,result,max_size)  do { \
        int i;                                  \
        for (i = 0; i < max_size; i++) {        \
                int ch = xinput();              \
                if (ch == EOF)                  \
                        break;                  \
                buf[i] = ch;                    \
        }                                       \
        result = i;                             \
} while (0) 
#define LEX_BUFFER_STATE YY_BUFFER_STATE
#define SET_BUFFER_STATE(s) do { \
        (s) = YY_CURRENT_BUFFER; \
        yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE)); \
} while (0)
#define RESTORE_BUFFER_STATE(s) do { \
        yy_delete_buffer(YY_CURRENT_BUFFER); \
        yy_switch_to_buffer(s); \
} while (0)

#else
/* AT&T Lex */
                                               
static void lex_set_buffer(FILE *fp);
static void lex_delete_buffer(LEX_BUFFER_STATE buf);
static int xinput(); 
static int xunput();
        
#undef unput
#define unput(c) xunput(c)
#undef input
#define input() xinput()

#define LEX_BUF_SIZE 16384
#define LEX_PUTBACK_SIZE 32
                                               
typedef struct {
        FILE *yyin;
        char *buffer;
        size_t bufsize;
        size_t level;
        char *ptr;
        char *putback;
        size_t pb_size;
        size_t pb_level;
} LEX_BUFFER_STATE;
LEX_BUFFER_STATE current_buffer;
 
#define SET_BUFFER_STATE(s) do { \
        (s) = current_buffer;    \
        lex_set_buffer(yyin);    \
} while (0)
#define RESTORE_BUFFER_STATE(s) do { \
        lex_delete_buffer(current_buffer); \
        current_buffer = (s); \
        yyin = current_buffer.yyin;  \
} while (0)
                                    
void
lex_set_buffer(FILE *fp)
{
        char *buf;
        size_t size;
        
        for (size = LEX_BUF_SIZE; size > 1; size /= 2)
                if (buf = grad_malloc(size))
                        break;
        if (!buf) {
                grad_log(GRAD_LOG_CRIT, _("not enough memory"));
                abort();
        }

        current_buffer.yyin = yyin;
        current_buffer.buffer = buf;
        current_buffer.bufsize = size;
        current_buffer.level = 0;
        current_buffer.ptr = current_buffer.buffer;
        current_buffer.pb_size = current_buffer.pb_level = 0;
        current_buffer.putback = NULL;
}
                
void
lex_delete_buffer(LEX_BUFFER_STATE buf)
{
        grad_free(buf.buffer);
        if (buf.putback)
                grad_free(buf.putback);
}

int
xinput()
{
        if (!yyin)
                return EOF;
        if (current_buffer.pb_level) 
                return current_buffer.putback[--current_buffer.pb_level];

        if (current_buffer.level <= 0) {
                int n;

                if (feof(yyin))
                        return 0;
                n = fread(current_buffer.buffer, 1,
                          current_buffer.bufsize, yyin);
                if (n <= 0)
                        return 0;
                current_buffer.level = n;
                current_buffer.ptr = current_buffer.buffer;
        }
        current_buffer.level--;
        return *current_buffer.ptr++;
}

int
xunput(int c)
{
        if (current_buffer.pb_level == current_buffer.pb_size) {
                char *putback;
                current_buffer.pb_size += LEX_PUTBACK_SIZE;
                putback = grad_emalloc(current_buffer.pb_size);
                memcpy(putback, current_buffer.putback,
                       current_buffer.pb_level);
                grad_free(current_buffer.putback);
                current_buffer.putback = putback;
        }
        current_buffer.putback[current_buffer.pb_level++] = c;
        return c;
}
                
#endif                                         

struct buffer_ctx {
        struct buffer_ctx *prev;
	grad_locus_t loc;
        ino_t i_node;
        FILE *yyin;
        LEX_BUFFER_STATE state;
};

static struct buffer_ctx *context_stack;

static struct buffer_ctx *ctx_lookup(ino_t ino);
static int push_source(char *name);
static int pop_source();

struct buffer_ctx *
ctx_lookup(ino_t ino)
{
        struct buffer_ctx *ctx;

        for (ctx = context_stack; ctx; ctx = ctx->prev)
                if (ctx->i_node == ino)
                        break;
        return ctx;
}
        
int
push_source(char *name)
{
        FILE *fp;
        struct buffer_ctx *ctx;
        struct stat st;
        
        if (stat(name, &st)) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("can't stat `%s'"), name);
                yyerror("can't include file");
                return 1;
        }

        if (grad_parser_source_locus.file && st.st_ino == source_inode) {
                yyerror("recursive inclusion");
                return 1;
        }
        if (ctx = ctx_lookup(st.st_ino)) {
                yyerror("recursive inclusion");
                if (ctx->prev)
                        grad_log_loc(GRAD_LOG_ERR, &ctx->prev->loc,
				     _("`%s' already included here"),
				     name);
                else
                        grad_log(GRAD_LOG_ERR, 
                                 _("`%s' already included at top level"),
                                 name);
                return 1;
        }
                
        fp = fopen(name, "r");
        if (!fp) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
                         _("can't open `%s'"),  name);
                yyerror("can't include file");
                return 1;
        }

        /* Push current context */
        if (grad_parser_source_locus.file) {
                ctx = grad_emalloc(sizeof(*ctx));
                ctx->loc = grad_parser_source_locus;
                ctx->i_node = source_inode;
                ctx->yyin = yyin;
                ctx->prev = context_stack;
                context_stack = ctx;

                /* Switch to the new context */
                yyin = fp;
                SET_BUFFER_STATE(ctx->state);
        } else {
#ifdef FLEX_SCANNER
                yyrestart(fp);
#else           
                yyin = fp;
                lex_set_buffer(yyin);
#endif
        }
        grad_parser_source_locus.file = name;
        grad_parser_source_locus.line = 1;
        source_inode = st.st_ino;
        return 0;
}

int
pop_source()
{
        struct buffer_ctx *ctx;

        if (!yyin) 
                return 1;
	
        fclose(yyin);
#ifndef FLEX_SCANNER
        lex_delete_buffer(current_buffer);
#endif
        if (!context_stack) {
		yyin = NULL;
                return 1;
        }
	/* Restore previous context */
        grad_parser_source_locus = context_stack->loc;
        source_inode = context_stack->i_node;
        RESTORE_BUFFER_STATE(context_stack->state);
        ctx = context_stack->prev;
        grad_free(context_stack);
        context_stack = ctx;
        return 0;
}
        
%}

WS [ \t][ \t]*
IDENT [a-zA-Z_\-0-9.!]+
O [0-7]
X [0-9a-fA-F]
D [0-9]{1,3}

%%
#.*\n   {
          if (strncmp(yytext+1, "debug", 5) == 0)
                  grad_enable_rule_debug(1);
          grad_parser_source_locus.line++; /* a comment */
        }
#.*     /* end-of-file comment */;
\$.*$   preproc();
NULL    return NUL;
{D}\.{D}\.{D}\.{D} |
{D}\.{D}\.{D}\.{D}\+ {
          yylval.string = addstring(yytext);
          return STRING;
}
{IDENT} {
          yylval.string = addstring(yytext);
          return STRING;
        }
\"[^"\\\n]*\" {
          yylval.string = addquote(yytext);
          return QUOTE;
        }
\"[^"\\\n]*\\\n {
          BEGIN(in_string);
          if (yyleng > 3)
		  grad_slist_append(slist, yytext+1, yyleng-3);
}
\"[^"\\\n]*\n {
          BEGIN(INITIAL);
          yyerror("unterminated character string");
          return BOGUS;
}
\"[^"\\\n]*\\[^xX0-9] {
          BEGIN(in_string);
          if (yyleng > 3)
                 grad_slist_append(slist, yytext+1, yyleng-3);
          grad_slist_append_char(slist, grad_decode_backslash(yytext[yyleng-1]));
}
\"[^"\\\n]*\\[xX]{X} |
\"[^"\\\n]*\\[xX]{X}{X} {
	  BEGIN(in_string);
	  grow_backslash_num(slist, yytext + 1, yyleng - 1, 16);
}
\"[^"\\\n]*\\{O} |
\"[^"\\\n]*\\{O}{O} |
\"[^"\\\n]*\\{O}{O}{O} {
          BEGIN(in_string);
          grow_backslash_num(slist, yytext + 1, yyleng - 1, 8); 
}
<in_string>[^"\\\n]*\\\n {
          grad_slist_append(slist, yytext, yyleng-2);
}
<in_string>[^"\\\n]*\n {
          BEGIN(INITIAL);
          grad_slist_clear(slist);
          yyerror("unterminated character string");
          return BOGUS;
}         
<in_string>[^"\\\n]*\\[^xX0-9] {
          if (yyleng > 2)
                   grad_slist_append(slist, yytext, yyleng-2);
          grad_slist_append_char(slist, grad_decode_backslash(yytext[yyleng-1]));
}
<in_string>[^"\\\n]*\\[xX]{X} |
<in_string>[^"\\\n]*\\[xX]{X}{X} {
	  grow_backslash_num(slist, yytext, yyleng, 16);
}
<in_string>[^"\\\n]*\\{O} |
<in_string>[^"\\\n]*\\{O}{O} |
<in_string>[^"\\\n]*\\{O}{O}{O} {
          grow_backslash_num(slist, yytext, yyleng, 8);
}
<in_string>[^"\\\n]*\" {
          BEGIN(INITIAL);
          grad_slist_append(slist, yytext, yyleng-1);
          grad_slist_append_char(slist, 0);
          yylval.string = grad_slist_finish(slist);
          return QUOTE;
}
{WS}    ;
\n      {
          grad_parser_source_locus.line++;
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
        return pop_source();
}

char *
addstring(char *s)
{
        int length = strlen(s);
        grad_slist_append(slist, s, length+1);
        return grad_slist_finish(slist);
}
        
char *
addquote(char *s)
{
        int length = strlen(s);
        if (length-2 > 0)
                grad_slist_append(slist, s+1, length-2);
        grad_slist_append_char(slist, 0);
        return grad_slist_finish(slist);
}

int
grad_parser_lex_init(char *name)
{
	int rc;

        slist = grad_slist_create();
        
        context_stack = NULL;
        grad_parser_source_locus.file = NULL;
        rc = push_source(name);
	if (rc)	
		grad_slist_free(&slist);
	return rc;
}

void
grad_parser_lex_finish()
{
        grad_slist_free(&slist);
#ifdef FLEX_SCANNER     
        yy_delete_buffer(YY_CURRENT_BUFFER); 
#endif
        yyin = NULL;
}

/* A rudimentary attempt to synchronize input after an error.
 * It is based on the assumption that only user names start
 * at column 0
 */
int
grad_parser_lex_sync()
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
				break;
                        } 
                }
        }
	return c;
}

#define isws(c) ((c) == ' ' || (c) == '\t')

/* Parse pre-processor directive. Currently supported directives are:
   $                  (Empty directive.)
   $INCLUDE filename
   $DEBUG [yYnN01] */
int
preproc()
{
        char *sp, *p;
        char *endp;
        int len;
        
        endp = yytext + yyleng;
        for (sp = yytext+1; sp < endp && isws(*sp); sp++)
                ;

        if (sp >= endp) 
                return 0;

        for (p = sp; p < endp && !isws(*p); p++)
                ;
        if (sp >= endp) 
                return 0;
        len = p - sp;

        for (; p < endp && isws(*p); p++)
                ;

        if (len == 7 && strncmp(sp, "INCLUDE", 7) == 0) {
                char *name;

                sp = p;
                for (; p < endp && !isws(*p); p++)
                        ;
                len = p - sp;
                if (len == 0) {
                        yyerror("empty file name");
                        return 1;
                }
                
                if (*sp != '/') {
                        /* append standard configuration directory path */
                        grad_slist_append(slist, grad_config_dir, strlen(grad_config_dir));
                        grad_slist_append_char(slist, '/');
                }
        
                grad_slist_append(slist, sp, len);
                grad_slist_append_char(slist, 0);
                name = grad_slist_finish(slist);
                return push_source(name);
        } else if (len == 5 && strncmp(sp, "DEBUG", 5) == 0) {
                int v;
                
                switch (*p) {
                case 0:
                case 'y':
                case 'Y':
                case '1':
                        v = 1;
                        break;
                case 'n':
                case 'N':
                case '0':
                        v = 0;
                        break;
                }
                grad_enable_rule_debug(v);
                return 0;
        }
        return 1;
}

void
grow_backslash_num(grad_slist_t slist, char *text, int len, int base)
{
	char *p = strchr(text, '\\');
	int n = p - text;
	grad_slist_append(slist, text, n);
	len -= n + 1;
	if (base == 16)
		len--;
	grad_slist_grow_backslash_num(slist, p, NULL, len, base);
}


