%{
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
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef lint
static char rcsid[] = 
        "@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
 
#include <radiusd.h>
#include <slist.h>
#include <obstack1.h>
#include <cfg.h>
 
#define YYMAXDEPTH 16

struct cfg_memblock {
	struct cfg_memblock *next;
	void (*destructor)();
	int line_num;
};

static struct cfg_memblock *cfg_memory_pool;
 
struct value_list {
	struct value_list *next;
	cfg_value_t val;
};

typedef struct vlist VLIST;
struct vlist {
	struct value_list *head;
	struct value_list *tail;
};

static VLIST *_cfg_vlist_create(cfg_value_t *val);
static VLIST *_cfg_vlist_append(VLIST *vlist, cfg_value_t *val);
static void _cfg_vlist_destroy(void*);
static void _cfg_free_memory_pool();
static void _cfg_run_begin(struct cfg_stmt *stmt, void *up_data);

static int yylex();
static char *typestr[] = {
	"integer",
	"boolean",
	"string",
	"network",
	"ipaddr",
	"port",
	"char",
	"host"
};
	 
struct syntax_block {
	struct syntax_block *prev;
	struct cfg_stmt *stmt;
	cfg_end_fp end;
	void *data;
};

static struct syntax_block *block;

static void _cfg_push_block(struct cfg_stmt *stmt, cfg_end_fp end, void *data);
static struct syntax_block *_cfg_pop_block();

int _cfg_make_argv(cfg_value_t **argv, char *keyword, VLIST *vlist);
void _cfg_free_argv(int argc, cfg_value_t *argv);

struct cfg_stmt *_cfg_find_keyword(struct cfg_stmt *stmt, char *str);
static int _get_value(cfg_value_t *arg, int type, void *base);
static struct obstack cfg_obstack;
char *cfg_filename;
int cfg_line_num;
static char *buffer;
static char *curp;

%}

%union {
        int number;
        int bool;
        UINT4 ipaddr;
        char *string;
        cfg_value_t value;
        cfg_network_t network;
	VLIST *vlist;
	struct cfg_stmt *stmt;
};

%token T_EOL
%token <string> T_WORD T_STRING
%token <number> T_NUMBER T_PUNCT 
%token <bool> T_BOOL
%token <ipaddr> T_IPADDR 

%type <ipaddr> netmask
%type <network> network
%type <stmt> keyword
%type <value> value
%type <vlist> value_list tag

%%

input       : list
            ;

list        : line
            | list line
            ;

line        : /* empty */ T_EOL
            | stmt 
            | error T_EOL
              {
		      yyclearin; yyerrok;
	      }
            ;

stmt        : simple_stmt 
            | block_stmt
            ;

block_stmt  : block_open list block_close T_EOL
            ;

block_open  : keyword tag '{'
              {
		      if ($1 && $1->type == CS_BLOCK) {
			      if ($1->handler) {
				      cfg_value_t *argv;
				      int rc;
				      int argc = _cfg_make_argv(&argv,
								$1->keyword,
								$2);
				      rc = $1->handler(argc, argv,
						       block->data,
						       $1->data);
				      _cfg_free_argv(argc, argv);
				      if (rc)
					      yyerror("syntax error");
			      }
			      _cfg_push_block($1->block, $1->end, $1->data);
		      } else {
			      if (block->stmt) {
				      radlog(L_ERR,
					     "%s:%d: %s",
					     cfg_filename, cfg_line_num,
					     _("unknown block statement"));
			      }
			      _cfg_push_block(NULL, NULL, NULL);
		      }
	      }
            ;  

block_close : '}'
              {
		      _cfg_pop_block();
	      }
            ;

tag         : /* empty */
              {
		      $$ = NULL;
	      }
            | value_list
            ;

simple_stmt : keyword value_list T_EOL
              {
		      if ($1) {
			      if ($1->handler) {
				      cfg_value_t *argv;
				      int rc;
				      int argc = _cfg_make_argv(&argv,
								$1->keyword,
								$2);
				      rc = $1->handler(argc, argv,
						       block->data,
						       $1->data);
				      _cfg_free_argv(argc, argv);
				      if (rc)
					      yyerror("syntax error");
			      }
		      } else if (block->stmt)
			      radlog(L_ERR,
				     "%s:%d: %s",
				     cfg_filename, cfg_line_num,
				     _("unknown keyword"));
	      }
            ;

value_list  : value
              {
		      $$ = _cfg_vlist_create(&$1);
	      }
            | value_list value
              {
		      $$ = _cfg_vlist_append($1, &$2);
	      }
            | value_list ',' value
              {
		      $$ = _cfg_vlist_append($1, &$3);
	      }
            ;

keyword     : T_WORD
              {
		      $$ = _cfg_find_keyword(block->stmt, $1);
	      }
            ;

value       : T_WORD
              {
		      $$.type = CFG_STRING;
		      $$.v.string = $1;
	      }
            | T_STRING
              {
		      $$.type = CFG_STRING;
		      $$.v.string = $1;
	      }
            | T_NUMBER
              {
		      $$.type = CFG_INTEGER;
		      $$.v.number = $1;
	      }
            | T_BOOL
              {
		      $$.type = CFG_BOOLEAN;
		      $$.v.bool = $1;
	      }
            | T_PUNCT
              {
		      $$.type = CFG_CHAR;
		      $$.v.ch = $1;
	      }
            | network
              {
		      $$.type = CFG_NETWORK;
		      $$.v.network = $1;
	      }
            | T_IPADDR ':' T_NUMBER
              {
		      $$.type = CFG_HOST;
		      $$.v.host.ipaddr = $1;
		      $$.v.host.port = $3;
	      }
            ; 

network     : T_IPADDR
              {
		      $$.ipaddr = $1;
		      $$.netmask = 0xffffffffL;
	      }
            | T_IPADDR slash netmask
              {
		      $$.ipaddr = $1;
		      $$.netmask = $3;
	      }
            ;

slash       : T_PUNCT
              {
		      if ($1 != '/')
			      YYERROR;
	      }
            ;

netmask     : T_IPADDR
            | T_NUMBER
              {
		      if ($1 > 32) {
			      radlog(L_ERR,
				     _("invalid netmask length: %d"), $1);
			      YYERROR;
		      }
		      $$ = (0xfffffffful >> (32-$1)) << (32-$1);
	      }
            ; 

%%

static void skipws();
static void skipline();
static void skipstmt();
static int isword(int c);
static char *copy_alpha();
static char *copy_string();
static int copy_digit();

static void putback(char *tok, int length);


#define ismath(c) (strchr("=!+-/*.", c)!=NULL)

int
yylex()
{
again:
        skipws();

        if (*curp == '#') { 
                skipline();
                goto again;
        } 
        if (*curp == '/' && curp[1] == '*') {
                int keep_line = cfg_line_num;

                curp += 2;
                do {
                        while (*curp != '*') {
                                if (*curp == 0) {
                                        radlog(L_ERR, 
                                               _("%s:%d: unexpected EOF in comment started at line %d"),
                                                cfg_filename, cfg_line_num, keep_line);
                                        return 0;
                                } else if (*curp == '\n')
                                        cfg_line_num++;
                                ++curp;
                        }
                } while (*++curp != '/');
                ++curp;
                goto again;
        }

        if (*curp == 0)
                return 0;
        
        if (isalpha(*curp)) {
                yylval.string = copy_alpha();
                return keyword();
        }

        if (*curp == '\"') {
                yylval.string = copy_string();
                return T_STRING;
        }
        
        if (isdigit(*curp)) {
                if (copy_digit()) {
                        /* IP address */
                        yylval.ipaddr = ip_strtoip(yylval.string);
                        return T_IPADDR;
                }
                yylval.number = strtol(yylval.string, NULL, 0);
                return T_NUMBER;
        } 

        if (*curp == ';') {
                curp++;
                return T_EOL;
        }

        if (ismath(*curp)) {
		yylval.number = *curp++;
		return T_PUNCT;
	}
        return *curp++;
}

void
putback(tok, length)
        char *tok;
        int length;
{
        if (length > curp - buffer) {
                radlog(L_CRIT, 
                       _("INTERNAL ERROR parsing %s near %d: out of putback space"),
                        cfg_filename, cfg_line_num);
                return;
        }       
        while (length--)        
                *--curp = tok[length];          
}

void
skipws()
{
        while (*curp && isspace(*curp)) {
                if (*curp == '\n')
                        cfg_line_num++;
                curp++;
        }
}

void
skipline()
{
        while (*curp && *curp != '\n')
                curp++;
}

int
isword(c)
        int c;
{
        return isalnum(c) || c == '_' || c == '-';
}

char *
copy_alpha()
{
        do {
		obstack_1grow(&cfg_obstack, *curp);
                curp++;
        } while (*curp && isword(*curp));
	obstack_1grow(&cfg_obstack, 0);
	return obstack_finish(&cfg_obstack);
}

char *
copy_string()
{
        int quote = *curp++;

        while (*curp) {
                if (*curp == quote) {
                        curp++;
                        break;
                }
		obstack_1grow(&cfg_obstack, *curp);
                curp++;
        } 
	obstack_1grow(&cfg_obstack, 0);
	return obstack_finish(&cfg_obstack);
}

int
copy_digit()
{
        int dot = 0;

        if (*curp == '0') {
                if (curp[1] == 'x' || curp[1] == 'X') {
			obstack_1grow(&cfg_obstack, *curp);
			curp++;
			obstack_1grow(&cfg_obstack, *curp);
			curp++;
                }
        }
        
        do {
		obstack_1grow(&cfg_obstack, *curp);
                if (*curp++ == '.')
                        dot++;
        } while (*curp && (isdigit(*curp) || *curp == '.'));
	obstack_1grow(&cfg_obstack, 0);
	yylval.string = obstack_finish(&cfg_obstack);
        return dot;
}

struct keyword booleans[] = {
	"on", 1,
	"off", 0,
	"yes", 1,
	"no", 0,
	0
};

int
keyword()
{
	int tok;
	
	if ((tok = xlat_keyword(booleans, yylval.string, -1)) != -1) {
		yylval.bool = tok;
		return T_BOOL;
	}
	return T_WORD;
}


int
yyerror(s)
        char *s;
{
        radlog(L_ERR, "%s:%d: %s", cfg_filename, cfg_line_num, s);
}
                
/* ************************************************************************* */
/* Internal functions */

void
_cfg_run_begin(stmt, up_data)
	struct cfg_stmt *stmt;
	void *up_data;
{
	for ( ; stmt->keyword; stmt++) {
		if (stmt->term)
			stmt->term(0, stmt->data, up_data);
		if (stmt->type == CS_BLOCK)
			_cfg_run_begin(stmt->block, stmt->data);
	}
}

void
_cfg_run_finish(stmt, up_data)
	struct cfg_stmt *stmt;
	void *up_data;
{
	for ( ; stmt->keyword; stmt++) {
		if (stmt->term)
			stmt->term(1, stmt->data, up_data);
		if (stmt->type == CS_BLOCK)
			_cfg_run_finish(stmt->block, stmt->data);
	}
}

void
_cfg_free_memory_pool()
{
	struct cfg_memblock *p, *next;

	p = cfg_memory_pool;
	while (p) {
		next = p->next;
                /*radlog(L_ERR, "%d, %p",p->line_num, p);*/
		if (p->destructor)
			p->destructor(p+1);
		efree(p);
		p = next;
	}
}

int
_cfg_make_argv(argv, keyword, vlist)
	cfg_value_t **argv;
	char *keyword;
	VLIST *vlist;
{
	int i, argc;
	struct value_list *p;

	if (vlist)
		for (argc = 1, p = vlist->head; p; argc++, p = p->next)
			;
	else
		argc = 1;
	*argv = emalloc(sizeof(**argv)*argc);
	(*argv)[0].type = CFG_STRING;
	(*argv)[0].v.string = keyword;
	if (vlist)
		for (i = 1, p = vlist->head; p; i++, p = p->next)
			(*argv)[i] = p->val;
	return argc;
}

void
_cfg_free_argv(argc, argv)
	int argc;
	cfg_value_t *argv;
{
	efree(argv);
}
		
VLIST *
_cfg_vlist_create(val)
	cfg_value_t *val;
{
	VLIST *vlist = cfg_malloc(sizeof(*vlist), _cfg_vlist_destroy);
	struct value_list *p = emalloc(sizeof(*p));

	p->val = *val;
	p->next = NULL;
	vlist->head = vlist->tail = p;
	return vlist;
}

VLIST *
_cfg_vlist_append(vlist, val)
	VLIST *vlist;
	cfg_value_t *val;
{
	struct value_list *p = emalloc(sizeof(*p));
	p->val = *val;
	p->next = NULL;
	vlist->tail->next = p;
	vlist->tail = p;
	return vlist;
}

void
_cfg_vlist_destroy(arg)
	void *arg;
{
	VLIST *vlist = arg;
	struct value_list *p, *next;

	p = vlist->head;
	while (p) {
		next = p->next;
		efree(p);
		p = next;
	}
}

void
_cfg_push_block(stmt, end, block_data)
	struct cfg_stmt *stmt;
	cfg_end_fp end;
	void *block_data;
{
	struct syntax_block *p = emalloc(sizeof(*p));
	p->stmt = stmt;
	p->end  = end;
	p->data = block_data;
	p->prev = block;
	block = p;
}

struct syntax_block *
_cfg_pop_block()
{
	struct syntax_block *p = block;

	if (p) {
		block = p->prev;
		if (p->end)
			p->end(block ? block->data : NULL, p->data);
		efree(p);
	}
	return block;
}

struct cfg_stmt *
_cfg_find_keyword(stmt, str)
	struct cfg_stmt *stmt;
	char *str;
{
	if (stmt)
		for (; stmt->keyword; stmt++) {
			if (strcmp(stmt->keyword, str) == 0)
				return stmt;
		}
	return NULL;
}

int
_get_value(arg, type, base)
	cfg_value_t *arg;
        int type;
	void *base;
{
        struct servent *s;
        UINT4 ipaddr;
        cfg_value_t value;

	value = *arg;
        switch (type) {
        case CFG_PORT:
                switch (value.type) {
                case CFG_INTEGER:
                        type = CFG_INTEGER;
                        break;
			
                case CFG_STRING:
                          s = getservbyname(value.v.string, "udp");
                          if (s) 
                                  value.v.number = ntohs(s->s_port);
                          else {
                                  radlog(L_ERR, 
                                         _("%s:%d: no such service: %s"),
                                         cfg_filename, cfg_line_num,
                                         value.v.string);
                                  return 0;
                          }
                          type = value.type = CFG_INTEGER;
                          break;
			  
                default:
                        break;
                }
                break;
                        
        case CFG_IPADDR:
                switch (value.type) {
                case CFG_IPADDR:
                        break;
			
                case CFG_INTEGER:
                        type = CFG_IPADDR;
                        break;
			
                case CFG_STRING:
                        ipaddr = ip_gethostaddr(value.v.string);
                        if (ipaddr == 0) {
                                radlog(L_ERR, 
                                       _("%s:%d: unknown host: %s"),
                                       cfg_filename, cfg_line_num,
                                       value.v.string);
                        }
                        value.v.ipaddr = ipaddr;
                        value.type = CFG_IPADDR;
                        break;

                default:
                        break;
                }
		break;
		
        }
        
        if (type != value.type) {
		cfg_type_error(type);
                return 0;
        }

        switch (type) {
        case CFG_INTEGER:
                *(int*) base = value.v.number;
                break;
		
        case CFG_STRING:
                string_replace((char**)base, value.v.string);
                break;
		
        case CFG_IPADDR:
                *(UINT4*) base = value.v.ipaddr;
                break;
		
        case CFG_BOOLEAN:
                *(int*) base = value.v.bool;
                break;
		
	case CFG_NETWORK:
		*(cfg_network_t *) base = value.v.network;
		break;
		
        default:
                radlog(L_CRIT,
                       _("INTERNAL ERROR at %s:%d: unknown datatype %d"),
                       __FILE__, __LINE__, type);
        }
	return 0;
}


/* ************************************************************************* */
/* Global functions */

void *
cfg_malloc(size, destructor)
	size_t size;
	void (*destructor)(void *);
{
	struct cfg_memblock *p = emalloc(size + sizeof(*p));
	p->next = cfg_memory_pool;
	p->destructor = destructor;
	p->line_num = cfg_line_num;
	cfg_memory_pool = p;
	return p+1;
}

void
cfg_type_error(type)
	int type;
{
	radlog(L_ERR, 
	       _("%s:%d: wrong datatype (should be %s)"),
	       cfg_filename, cfg_line_num, typestr[type]);
}

void
cfg_argc_error(few)
	int few;
{
	radlog(L_ERR,
	       "%s:%d: %s",
	       cfg_filename, cfg_line_num,
	       few ? _("too few arguments") : _("too many arguments"));
}

#define _check_argc(argc, max) \
 if (argc-1 > max) {\
     radlog(L_ERR, "%s:%d: %s", cfg_filename, cfg_line_num, _("too many arguments"));\
     return 0;\
 }		

int
cfg_get_ipaddr(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_IPADDR, handler_data);
}

int
cfg_get_integer(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_INTEGER, handler_data);
}

int
cfg_get_string(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_STRING, handler_data);
}

int
cfg_get_boolean(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_BOOLEAN, handler_data);
}

int
cfg_get_network(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_NETWORK, handler_data);
}

int
cfg_get_port(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	_check_argc(argc, 1);
	return _get_value(&argv[1], CFG_PORT, handler_data);
}

int
cfg_read(fname, syntax, data)
	char *fname;
	struct cfg_stmt *syntax;
	void *data;
{
        struct stat st;
        int fd;
        extern int yydebug;

	cfg_memory_pool = NULL;
	block = NULL;
	
        cfg_filename = fname;
	_cfg_push_block(syntax, NULL, data);
        if (stat(cfg_filename, &st)) {
                radlog(L_ERR|L_PERROR, _("can't stat `%s'"), cfg_filename);
                return -1;
        }
        fd = open(cfg_filename, O_RDONLY);
        if (fd == -1) {
                if (errno != ENOENT)
                        radlog(L_ERR|L_PERROR, 
                                _("can't open config file `%s'"), cfg_filename);
                return -1;
        }
        buffer = cfg_malloc(st.st_size+1, NULL);
        
        read(fd, buffer, st.st_size);
        buffer[st.st_size] = 0;
        close(fd);
        curp = buffer;

        radlog(L_INFO, _("reading %s"), cfg_filename);
        cfg_line_num = 1;

        if (strncmp(curp, "#debug", 6) == 0) {
		/* Note: can't check YYDEBUG here, because some yaccs
		   (most notably, sun's) define YYDEBUG after including
		   code block */     
                yydebug = 1;
        } else {
                yydebug = 0;
        }

	obstack_init(&cfg_obstack);
	_cfg_run_begin(syntax, data);
	
        /* Parse configuration */
        yyparse();

	_cfg_run_finish(syntax, data);

        /* Clean up the things */
	while (_cfg_pop_block())
		;

	_cfg_free_memory_pool();
	obstack_free(&cfg_obstack, NULL);

        return 0;
}       

