/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA. */
%e 8000
%p 15000
%x in_string
%{
#ifndef lint
static char rcsid[] = 
"$Id$";
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
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include <radius.h>

#include <obstack1.h>
#include <parser.h>
#include <users_gram.h>

extern void enable_usr_dbg(int);
static char *addstring();
static char *addquote();
static int preproc();

static struct obstack stack; /* Obstack for keeping string values */ 
char *source_filename;       /* Current filename */
ino_t source_inode;          /* Inode of the current source (for preventing
                                recursive inclusion */
int source_line_num;         /* Current line number */
        
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
lex_set_buffer(fp)
        FILE *fp;
{
        char *buf;
        size_t size;
        
        for (size = LEX_BUF_SIZE; size > 1; size /= 2)
                if (buf = radxmalloc(size))
                        break;
        if (!buf) {
                radlog(L_CRIT, _("not enough memory"));
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
lex_delete_buffer(buf)
        LEX_BUFFER_STATE buf;
{
        efree(buf.buffer);
        if (buf.putback)
                efree(buf.putback);
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
xunput(c)
        int c;
{
        if (current_buffer.pb_level == current_buffer.pb_size) {
                char *putback;
                current_buffer.pb_size += LEX_PUTBACK_SIZE;
                putback = emalloc(current_buffer.pb_size);
                memcpy(putback, current_buffer.putback,
                       current_buffer.pb_level);
                efree(current_buffer.putback);
                current_buffer.putback = putback;
        }
        current_buffer.putback[current_buffer.pb_level++] = c;
        return c;
}
                
#endif                                         

struct buffer_ctx {
        struct buffer_ctx *prev;
        char *filename;
        int line;
        ino_t i_node;
        FILE *yyin;
        LEX_BUFFER_STATE state;
};

static struct buffer_ctx *context_stack;

static struct buffer_ctx *ctx_lookup(ino_t ino);
static int push_source(char *name);
static int pop_source();

struct buffer_ctx *
ctx_lookup(ino)
        ino_t ino;
{
        struct buffer_ctx *ctx;

        for (ctx = context_stack; ctx; ctx = ctx->prev)
                if (ctx->i_node == ino)
                        break;
        return ctx;
}
        
int
push_source(name)
        char *name;
{
        FILE *fp;
        struct buffer_ctx *ctx;
        struct stat st;
        
        if (stat(name, &st)) {
                radlog(L_ERR|L_PERROR,
		       _("can't stat `%s'"), name);
                yyerror("can't include file");
                return 1;
        }

        if (source_filename && st.st_ino == source_inode) {
                yyerror("recursive inclusion");
                return 1;
        }
        if (ctx = ctx_lookup(st.st_ino)) {
                yyerror("recursive inclusion");
                if (ctx->prev)
                        radlog(L_ERR, _("%s:%d: `%s' already included here"),
                               ctx->prev->filename, ctx->prev->line, name);
                else
                        radlog(L_ERR, _("`%s' already included at top level"),
                               name);
                return 1;
        }
                
        fp = fopen(name, "r");
        if (!fp) {
                radlog(L_ERR|L_PERROR, _("can't open `%s'"),  name);
                yyerror("can't include file");
                return 1;
        }

        /* Push current context */
        if (source_filename) {
                ctx = mem_alloc(sizeof(*ctx));
                ctx->filename = source_filename;
                ctx->line = source_line_num;
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
        source_filename = name;
        source_line_num = 1;
        source_inode = st.st_ino;
        return 0;
}

int
pop_source()
{
        struct buffer_ctx *ctx;

        fclose(yyin);
#ifndef FLEX_SCANNER
        lex_delete_buffer(current_buffer);
#endif
        if (!context_stack) {
                yyin = NULL;
                return 1;
        }
        /* Restore previous context */
        source_filename = context_stack->filename;
        source_line_num = context_stack->line;
        source_inode = context_stack->i_node;
        RESTORE_BUFFER_STATE(context_stack->state);
        ctx = context_stack->prev;
        mem_free(context_stack);
        context_stack = ctx;
        return 0;
}
        
#define to_num(c) ((c)-'0')
%}

WS [ \t][ \t]*
IDENT [a-zA-Z_\-0-9.!]+
O [0-7]
X [0-9a-fA-F]
D [0-9]{1,3}

%%
#.*\n   {
          if (strncmp(yytext+1, "debug", 5) == 0)
                  enable_usr_dbg(1);
          source_line_num++; /* a comment */
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
                 obstack_grow(&stack, yytext+1, yyleng-3);
}
\"[^"\\\n]*\n {
          BEGIN(INITIAL);
          yyerror("unterminated character string");
          return BOGUS;
}
\"[^"\\\n]*\\[^xX0-9] {
          BEGIN(in_string);
          if (yyleng > 3)
                 obstack_grow(&stack, yytext+1, yyleng-3);
          obstack_1grow(&stack, backslash(yytext[yyleng-1]));
}
<in_string>[^"\\\n]*\\\n {
          obstack_grow(&stack, yytext, yyleng-2);
}
<in_string>[^"\\\n]*\n {
          BEGIN(INITIAL);
          obstack_finish(&stack);
          yyerror("unterminated character string");
          return BOGUS;
}         
<in_string>[^"\\\n]*\\[^xX0-9] {
          if (yyleng > 2)
                   obstack_grow(&stack, yytext, yyleng-2);
          obstack_1grow(&stack, backslash(yytext[yyleng-1]));
}
<in_string>[^"\\\n]*\\{O} |
<in_string>[^"\\\n]*\\{O}{O} |
<in_string>[^"\\\n]*\\{O}{O}{O} {
          int i = yyleng;
          int c = 0;

          while (i > 0 && yytext[i] != '\\')
                  i--;
          obstack_grow(&stack, yytext, i);
          for (i++; i < yyleng; i++) 
                  c = c*8 + to_num(yytext[i]);
          obstack_1grow(&stack, c);
}
<in_string>[^"\\\n]*\" {
          BEGIN(INITIAL);
          obstack_grow(&stack, yytext, yyleng-1);
          obstack_1grow(&stack, 0);
          yylval.string = obstack_finish(&stack);
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
        return pop_source();
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
        obstack_init(&stack);
        
        context_stack = NULL;
        source_filename = NULL;
        return push_source(name);
}

void
done_lex()
{
        obstack_free(&stack, NULL);
#ifdef FLEX_SCANNER     
        yy_delete_buffer(yy_current_buffer); 
#endif
        yyin = NULL;
}

/* A rudimentary attempt to synchronize input after an error.
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
                        obstack_grow(&stack, radius_dir, strlen(radius_dir));
                        obstack_1grow(&stack, '/');
                }
        
                obstack_grow(&stack, sp, len);
                obstack_1grow(&stack, 0);
                name = obstack_finish(&stack);
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
                enable_usr_dbg(v);
                return 0;
        }
        return 1;
}
