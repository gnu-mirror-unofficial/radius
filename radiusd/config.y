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

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h> 
#include <radiusd.h>
 
#define YYMAXDEPTH 16

#ifdef USE_SNMP
typedef struct netlist Netlist;
struct netlist {
        Netlist *next;
        char *name;
        ACL *acl;
};
static Netlist *netlist;
#endif

#define AT_ANY    0
#define AT_INT    1
#define AT_STRING 2
#define AT_IPADDR 3
#define AT_BOOL   4
#define AT_PORT   5
 
static char *typestr[] = {
        "any",
        "numeric",
        "string",
        "IP address",
        "boolean",
        "port"
};

static int syslog_severity[] = {
        LOG_ALERT,
        LOG_CRIT,    
        LOG_DEBUG,   
        LOG_EMERG,   
        LOG_ERR,     
        LOG_INFO,    
        LOG_NOTICE,  
        LOG_WARNING,
};
         
struct category_def {
        Chanlist *head, *tail;
        int level;
} cat_def;

extern time_t delayed_hup_wait;
extern int keyword();

static char *filename;
static char line_num;
static char *buffer;
static char *curp;
static int expect_string; 
static int in_category;

static Channel channel;

static void skipws();
static void skipline();
static void skipstmt();
static int isword(int c);
static void copy_alpha();
static void copy_string();
static int copy_digit();

#ifdef USE_SNMP
static char * ident_string(char *);
static void add_netlist(char *name, ACL *list);
static void free_netlist();
static ACL *find_netlist(char*);
#endif

static int yylex();
static void putback(char *tok, int length);

static int got_listen;
static int first_time = 1;
static int debug_config;

static void asgn(void *base, Value *value, int type, int once);
static void obsolete(char *stmt, int ign);
 
%}

%union {
        int number;
        int bool;
        UINT4 ipaddr;
        char string[256];
        char *sptr;
        Value value;
        HOSTDECL hostdecl;
        struct {
                HOSTDECL *head;
                HOSTDECL *tail;
        } hostlist;
        struct {
                int cat;
                int pri;
        } category_name;
#ifdef USE_SNMP
        struct {
                ACL *head, *tail;
        } netlist;
        ACL *acl;
#else
        int netlist, acl;
#endif
};

%token EOL
%token T_ALLOW T_AUTH T_CATEGORY T_DENY T_DETAIL T_EXPWARNING T_FILE T_GUILE
%token T_INFO T_IDENT T_LEVEL T_LISTEN T_LOGGING T_NETWORK T_MAIN T_OPTION 
%token T_USEDBM T_CHECKRAD_ASSUME_LOGGED T_DELAY T_DETAIL T_HOST           
%token T_EXEC_PROGRAM_GROUP T_EXEC_PROGRAM_USER T_LOAD T_LOAD_PATH T_LOG_DIR
%token T_MAX_REQUESTS T_MESSAGE T_PORT T_REQUEST_CLEANUP_DELAY T_RETRY T_SPAWN 
%token T_STRIP_NAMES T_TTL T_USERNAME_CHARS T_USR2DELAY T_RESOLVE T_MAX_THREADS

%token T_SOURCE_IP T_ACCT_DIR T_ACCT T_CNTL T_PROXY T_CHANNEL
%token T_SYSLOG T_NOTIFY T_SNMP T_COMMUNITY T_ACL

%token <number> T_FACILITY T_LOGLEVEL T_LOGOPT T_SEVERITY T_SNMP_ACCESS 
%token <number> T_NUMBER
%token <ipaddr> T_IPADDR
%token <string> T_STRING
%token <bool> T_BOOL
%token <number> T_MESGDEF

%type <string> channel_name
%type <ipaddr> netmask
%type <netlist> netlist
%type <acl> acl network
%type <value> value
%type <number> facility 
%type <number> category severity
%type <category_name> category_name
%type <hostdecl> host
%type <hostlist> hostlist listen_stmt
%type <number> obs_option_list obs_option_string level level_list

%%
                
input           : list
                ;

list            : line
                | list line
                ;

line            : /* empty */ EOL
                | stmt EOL
                | error EOL
                  {
                          expect_string = 0;
                          yyclearin; yyerrok;
                  }
                ;

stmt            : logging_stmt
                | options_stmt
                | notify_stmt
                | usedbm_stmt
                | auth_stmt
                | acct_stmt
                | proxy_stmt 
                | cntl_stmt
                | snmp_stmt
                | guile_stmt
                | message_stmt
                ;


options_stmt    : T_OPTION '{' option_list '}'
                ;

option_list     : option_line
                | option_list option_line
                | option_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

option_line     : /* empty */ EOL
                | option_def EOL
                ;

option_def      : T_SOURCE_IP value
                  {
                          asgn(&myip, &$2, AT_IPADDR, 0);
                  }
                | T_MAX_REQUESTS value
                  {
                          asgn(&config.max_requests, &$2, AT_INT, 0);
                  }
                | T_MAX_THREADS value
                  {
                          asgn(&max_threads, &$2, AT_INT, 0);
                  }
                | T_LOG_DIR value
                  {
                          asgn(&radlog_dir, &$2, AT_STRING, 1);
                  }
                | T_ACCT_DIR value
                  {
                          asgn(&radacct_dir, &$2, AT_STRING, 1);
                  }
                | T_EXEC_PROGRAM_USER value
                  {
                          asgn(&config.exec_user, &$2, AT_STRING, 0);
                  }
                | T_EXEC_PROGRAM_GROUP value
                  {
                          obsolete("exec-program-group", 1);
                  }
                | T_USERNAME_CHARS value
                  {
                          asgn(&username_valid_chars, &$2, AT_STRING, 0);
                  }
                | T_RESOLVE value
                  {
                          asgn(&resolve_hostnames, &$2, AT_BOOL, 0);
                  }
                | T_USR2DELAY value
                  {
                          obsolete("usr2delay", 1);
                  }
                ;

errmark         : EOL
                | '}'
                  {
                          putback("}", 1);
                  }
                ;

        /* Auth statement */
auth_stmt       : auth '{' auth_list '}'
                  {
                          if (!got_listen)
                                  listen_auth(NULL);
                  }
                ;

auth            : T_AUTH
                  {
                          got_listen = 0;
                  }
                ;

auth_list       : auth_line
                | auth_list auth_line
                | auth_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

auth_line       : /* empty */ EOL
                | auth_def EOL
                ;

auth_def        : listen_stmt
                  {
                          got_listen = 1;
                          listen_auth($1.head);
                          free_slist((struct slist*)$1.head, NULL);
                  }
                | T_PORT value
                  {
                          asgn(&auth_port, &$2, AT_PORT, 0);
                  }      
                | T_SPAWN value
                  {
                          obsolete("spawn", 1);
                  }      
                | T_TTL value
                  {
                          asgn(&request_class[R_AUTH].ttl, &$2, AT_INT, 0);
                  }      
                | T_MAX_REQUESTS value
                  {
                          asgn(&request_class[R_AUTH].max_requests, &$2,
                               AT_INT, 0);
                  }      
                | T_REQUEST_CLEANUP_DELAY value
                  {
                          asgn(&request_class[R_AUTH].cleanup_delay, &$2,
                               AT_INT, 0);
                  }      
                | T_DETAIL value
                  {
                          asgn(&auth_detail, &$2, AT_BOOL, 0);
                  }      
                | T_STRIP_NAMES value
                  {
                          asgn(&strip_names, &$2, AT_BOOL, 0);
                  }      
                | T_CHECKRAD_ASSUME_LOGGED value
                  {
                          asgn(&config.checkrad_assume_logged, &$2,
                               AT_BOOL, 0);
                  }      
                | T_EXPWARNING value
                  {
                          asgn(&warning_seconds, &$2, AT_INT, 0);
                  }
                ;

        /* Acct statement */
acct_stmt       : acct '{' acct_list '}'
                  {
                          if (!got_listen)
                                  listen_acct(NULL);
                  }
                ;

acct            : T_ACCT
                  {
                          got_listen = 0;
                  }
                ;

acct_list       : acct_line
                | acct_list acct_line
                | acct_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

acct_line       : /* empty */ EOL
                | acct_def EOL
                ;

acct_def        : listen_stmt
                  {
                          got_listen = 1;
                          listen_acct($1.head);
                          free_slist((struct slist*)$1.head, NULL);
                  }
                | T_PORT value
                  {
                          asgn(&acct_port, &$2, AT_PORT, 0);
                  }      
                | T_SPAWN value
                  {
                          obsolete("spawn", 1);
                  }      
                | T_TTL value
                  {
                          asgn(&request_class[R_AUTH].ttl, &$2, AT_INT, 0);
                  }      
                | T_MAX_REQUESTS value
                  {
                          asgn(&request_class[R_AUTH].max_requests, &$2,
                               AT_INT, 0);
                  }      
                | T_REQUEST_CLEANUP_DELAY value
                  {
                          asgn(&request_class[R_AUTH].cleanup_delay, &$2,
                               AT_INT, 0);
                  }      
                | T_DETAIL value
                  {
                          asgn(&acct_detail, &$2, AT_BOOL, 0);
                  }      
                ;


        /* Proxy statement */
proxy_stmt      : T_PROXY '{' proxy_list '}'
                ;

proxy_list      : proxy_line
                | proxy_list proxy_line
                | proxy_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

proxy_line      : /* empty */ EOL
                | proxy_def EOL
                ;

proxy_def       : T_MAX_REQUESTS value
                  {
                          asgn(&request_class[R_PROXY].max_requests, &$2,
                               AT_INT, 0);
                  }
                | T_REQUEST_CLEANUP_DELAY value
                  {
                          asgn(&request_class[R_PROXY].cleanup_delay, &$2,
                               AT_INT, 0);
                  }
                ;

        /* Logging control: */

logging_stmt    : T_LOGGING '{' logging_list '}'
                ;

logging_list    : logging
                | logging_list logging
                ;

logging         : /* empty */ EOL
                | channel_stmt EOL
                | category_stmt EOL
                | error EOL
                  {
                          expect_string = 0;
                          in_category = 0;
                          yyclearin;
                          yyerrok;
                  }
                ;

        /* Logging control: channel definition */

channel_stmt    : T_CHANNEL channel_name '{' channel_list '}'
                  {
                          if (channel.mode == LM_UNKNOWN) {
                                  radlog(L_ERR,
                                      _("%s:%d: no channel mode for `%s'"), 
                                        filename, line_num, $2);
                          } else {
                                  channel.name = $2;
                                  register_channel(&channel);
                                  if (channel.mode == LM_FILE)
                                          efree(channel.id.file);
                          }
                  }
                ;

channel_name    : { expect_string = 1; } T_STRING
                  {
                          expect_string = 0;
                          channel.mode = LM_UNKNOWN;
                          strcpy($$, $2);
                  }
                ;

channel_list    : channel_def
                | channel_list channel_def
                ;

channel_def     : /* empty */ EOL
                | T_FILE T_STRING EOL
                  {
                          channel.mode = LM_FILE;
                          channel.id.file = estrdup($2);
                  }
                | T_SYSLOG facility '.' T_SEVERITY EOL
                  {
                          channel.mode = LM_SYSLOG;
                          channel.id.prio = $2 | syslog_severity[$4] ;
                  }
                | T_LOGOPT T_BOOL EOL
                  {
                          if ($2)
                                  channel.options |= $1;
                          else
                                  channel.options &= ~$1;
                  }
                | T_OPTION { expect_string=1; } obs_option_list EOL
                  {
                          expect_string = 0;
                          obsolete("option", 0);
                          channel.options |= $3;
                  }
                ;

facility        : T_FACILITY
                | T_AUTH
                  {
                          $$ = LOG_AUTH;
                  }
                | T_NUMBER
                ;


        /* Logging control: category definition */

category_stmt   : T_CATEGORY category_name begin category_list end
                  {
                          switch ($2.cat) {
                          case L_AUTH:
                                  log_mode = cat_def.level;
                                  break;
                          default:
                                  if (cat_def.level)
                                          radlog(L_WARN,
                           _("%s:%d: no levels applicable for this category"),
                                                 filename, line_num);

                          }
                          in_category = 0;
                          register_category($2.cat, $2.pri, cat_def.head);
                          free_chanlist(cat_def.head);
                  }
                ;

begin           : '{'
                  {
                          cat_def.level = 0;
                          cat_def.head = cat_def.tail = NULL;
                  }
                ;

end             : '}'
                ;

category_name   : category
                  {
                          in_category = $1;
                          $$.cat = $1;
                          $$.pri = -1;
                  }
                | severity
                  {
                          in_category = $1;
                          $$.cat = -1;
                          $$.pri = $1;
                  }
                | category '.' severity
                  {
                          in_category = $1|$3;
                          $$.cat = $1;
                          $$.pri = $3;
                  }
                | category '.' '*'
                  {
                          in_category = $1;
                          $$.cat = $1;
                          $$.pri = -1;
                  }
                ;

category        : T_MAIN
                  {
                          $$ = L_ACCT;
                  }
                | T_AUTH
                  {
                          $$ = L_AUTH;
                  }
                | T_ACCT
                  {
                          $$ = L_ACCT;
                  }
                | T_SNMP
                  {
                          $$ = L_SNMP;
                  }
                | T_PROXY
                  {
                          $$ = L_PROXY;
                  }
                | '*'
                  {
                          $$ = -1;
                  }
                ;

severity        : T_SEVERITY
                  {
                          $$ = L_UPTO($1);
                  }
                | '=' T_SEVERITY
                  {
                          $$ = L_MASK($2);
                  }
                | '!' T_SEVERITY
                  {
                          $$ = L_UPTO(L_DEBUG) & ~L_MASK($2);
                  }
                ;

category_list   : category_def
                | category_list category_def
                | category_list error '}'
                  {
                          /*free_chanlist?*/
                          expect_string = 0;
                          putback("}", 1);
                          yyclearin;
                          yyerrok;  
                  }
                ;

category_def    : T_CHANNEL { expect_string = 1; } T_STRING EOL
                  {
                          Channel *channel = channel_lookup($3);
                          expect_string = 0;
                          if (!channel) {
                                  radlog(L_ERR,
                                         _("%s:%d: channel `%s' not defined"),
                                         filename, line_num, $3);
                          } else {
                                  Chanlist *chanlist = make_chanlist(channel);
                                  if (cat_def.tail)
                                          cat_def.tail->next = chanlist;
                                  else
                                          cat_def.head = chanlist;
                                  cat_def.tail = chanlist;
                          }
                  }
                | T_LOGLEVEL T_BOOL EOL
                  {
                          if ($2)
                                  cat_def.level |= $1;
                          else
                                  cat_def.level &= ~$1;
                  }
                | begin_level level_list EOL
                  {
                          expect_string = 0;
                          if ((in_category & L_CATMASK) == L_AUTH) 
                                  cat_def.level |= $2;
                  }                       
                ;

begin_level     : T_LEVEL
                  {
                          if (in_category & L_MASK(L_DEBUG)) {
                                  expect_string = 1;
                                  clear_debug();
                          } else if ((in_category & L_CATMASK) == L_AUTH) {
                                  expect_string = 1;
                                  obsolete("level", 0);
                          }
                  }
                ;

level_list      : level
                | level_list ','level
                  {
                          $$ = $1 | $3;
                  }
                ;

level           : T_STRING
                  {
                          if (in_category & L_MASK(L_DEBUG)) {
                                  if (set_module_debug_level($1, -1))
                                          radlog(L_WARN,
                                         _("%s:%d: no such module name: %s"),
                                                 filename, line_num, $1);
                                  $$ = 0;
                          } else if (in_category & L_AUTH) {
                                  /* Backward compatibility */
                                  if (strcmp($1, "auth") == 0)
                                          $$ = RLOG_AUTH;
                                  else if (strcmp($1, "pass") == 0)
                                          $$ = RLOG_AUTH_PASS;
                                  else if (strcmp($1, "failed_pass") == 0)
                                          $$ = RLOG_FAILED_PASS;
                                  else {
                                          radlog(L_WARN,
                                         _("%s:%d: invalid level: %s"),
                                                 filename, line_num, $1);
                                          $$ = 0;
                                  }
                          } else {
                                  yyerror("level syntax");
                                  YYERROR;
                          }
                  }
                | T_STRING '=' T_NUMBER
                  {
                          if (!(in_category & L_MASK(L_DEBUG))) {
                                  yyerror("level syntax");
                                  YYERROR;
                          }
                          if (set_module_debug_level($1, $3))
                                  radlog(L_WARN,
                                         _("%s:%d: no such module name: %s"),
                                         filename, line_num, $1);
                  }
                ;


usedbm_stmt     : T_USEDBM T_BOOL
                  {
#ifdef USE_DBM
                          use_dbm = $2;
                          if (debug_config)
                                  radlog(L_DEBUG, _("use dbm: %d"), use_dbm);
#else
                          radlog(L_WARN,
                                 _("%s:%d: usedbm statement ignored: radiusd compiled without DBM support"),
                                 filename, line_num);
#endif
                  }
                ;

        /* SNMP server parameters */

snmp_stmt       : T_SNMP '{' snmp_list '}'
                  {
#ifndef USE_SNMP
                          radlog(L_WARN,
                                 _("%s:%d: snmp statement ignored: radiusd compiled without snmp support"),
                                 filename, line_num);
#endif
                  }
                ;

netmask         : T_IPADDR
                | T_NUMBER
                  {
                          if ($1 > 32) {
                                  radlog(L_ERR, _("invalid netmask: %d"), $1);
                                  YYERROR;
                          }
                          $$ = (0xfffffffful >> (32-$1)) << (32-$1);
                  }
                ;  

network         : T_IPADDR '/' netmask
                  {
#ifdef USE_SNMP
                          ACL *p = alloc_entry(sizeof(*p));

                          p->ipaddr = htonl($1);
                          p->netmask = htonl($3);
                          $$ = p;
#endif
                  }
                | T_IPADDR
                  {
#ifdef USE_SNMP
                          ACL *p = alloc_entry(sizeof(*p));

                          p->ipaddr = htonl($1);
                          p->netmask = 0xfffffffful;
                          $$ = p;
#endif
                  }
                ;

netlist         : network
                  {
#ifdef USE_SNMP
                          $$.head = $$.tail = $1;
#endif
                  }
                | netlist network
                  {
#ifdef USE_SNMP
                          $1.tail->next = $2;
                          $1.tail = $2;
                          $$ = $1;
#endif
                  }
                ;

acl             : T_STRING
                  {
#ifdef USE_SNMP
                          if (($$ = find_netlist($1)) == NULL) {
                                  radlog(L_ERR, _("%s:%d: no such acl: %s"),
                                      filename, line_num, $1);
                                  YYERROR;
                          }
#else
                          $$ = 0;
#endif
                  }
                ;

snmp_list       : snmp_line
                | snmp_list snmp_line
                | snmp_list error errmark
                  {
                         yyclearin;
                         yyerrok;
                  }
                ;

snmp_line       : /* empty */ EOL
                | snmp_def EOL
                ;

snmp_def        : T_IDENT T_STRING
                  {
#ifdef USE_SNMP
                          if (server_id)
                                 efree(server_id);
                          server_id = ident_string($2);
#endif
                  }
                | T_PORT value
                  {
#ifdef USE_SNMP
                          asgn(&snmp_port, &$2, AT_PORT, 0);
#endif
                  }      
                | T_SPAWN value
                  {
                          obsolete("spawn", 1);
                  }      
                | T_TTL value
                  {
#ifdef USE_SNMP
                          asgn(&request_class[R_SNMP].ttl, &$2, AT_INT, 0);
#endif
                  }      
                | T_MAX_REQUESTS value
                  {
#ifdef USE_SNMP
                          asgn(&request_class[R_SNMP].max_requests, &$2,
                               AT_INT, 0);
#endif
                  }      
                | T_REQUEST_CLEANUP_DELAY value
                  {
#ifdef USE_SNMP
                          asgn(&request_class[R_SNMP].cleanup_delay, &$2,
                               AT_INT, 0);
#endif
                  }      
                | T_COMMUNITY T_STRING T_SNMP_ACCESS
                  {
#ifdef USE_SNMP
                          if (snmp_find_community($2)) {
                                  radlog(L_ERR,
                                      _("%s:%d: community %s already declared"),
                                      filename, line_num, $2);
                          } else {
                                  snmp_add_community($2, $3);
                          }
#endif
                  }
                | T_NETWORK T_STRING netlist
                  {
#ifdef USE_SNMP
                          add_netlist($2, $3.head);
#endif
                  }
                | acl_stmt
                ;

acl_stmt        : T_ACL '{' acl_list '}'
                ;

acl_list        : acl_line
                | acl_list acl_line
                | acl_list error errmark
                  {
                         yyclearin;
                         yyerrok;
                  }
                ;

acl_line        : /* empty */ EOL
                | acl_def EOL
                ;

acl_def         : T_ALLOW acl T_STRING
                  {
#ifdef USE_SNMP
                          Community *comm = snmp_find_community($3);
                          if (!comm) {
                                  radlog(L_ERR, 
                                      _("%s:%d: undefined community %s"),
                                      filename, line_num, $2);
                          } else
                                  snmp_add_acl($2, comm);
#endif
                  }
                | T_DENY acl
                  {
#ifdef USE_SNMP
                          snmp_add_acl($2, NULL);
#endif
                  }
                ;

        /* Assignments */

value           : T_STRING
                  {
                          $$.type = AT_STRING;
                          strncpy($$.v.string, $1, sizeof($$.v.string));
                          $$.v.string[sizeof($$.v.string)-1] = 0;
                  }
                | T_IPADDR
                  {
                          $$.type = AT_IPADDR;
                          $$.v.ipaddr = $1;
                  }
                | '*'
                  {
                          $$.type = AT_IPADDR;
                          $$.v.ipaddr = INADDR_ANY;
                  }
                | T_BOOL
                  {
                          $$.type = AT_BOOL;
                          $$.v.bool = $1;
                  }
                | T_NUMBER
                  {
                          $$.type = AT_INT;
                          $$.v.number = $1;
                  }
                ;

listen_stmt     : T_LISTEN hostlist
                  {
                          $$ = $2;
                  }
                | T_LISTEN hostlist error 
                  {
                          free_slist((struct slist*)$2.head, NULL);
                          yyclearin; yyerrok;
                          $$.head = NULL;
                  }
                ;

hostlist        : host
                  {
                          $$.head = alloc_entry(sizeof(*$$.head));
                          $$.head->ipaddr = $1.ipaddr;
                          $$.head->port = $1.port;
                          $$.head->next = NULL;
                          $$.tail = $$.head;
                  }
                | hostlist ',' host
                  {
                          HOSTDECL *hp = alloc_entry(sizeof(*hp));
                          hp->ipaddr = $3.ipaddr;
                          hp->port = $3.port;
                          hp->next = NULL;
                          $$.tail->next = hp;
                          $$.tail = hp;
                  }
                ;

host            : value
                  {
                          asgn(&$$.ipaddr, &$1, AT_IPADDR, 0);
                          $$.port = 0;
                  }
                | value ':' value
                  {
                          asgn(&$$.ipaddr, &$1, AT_IPADDR, 0);
                          asgn(&$$.port, &$3, AT_PORT, 0);
                  }
                ;

guile_stmt      : T_GUILE '{' guile_list '}'
                  {
#ifdef USE_SERVER_GUILE
                          use_guile = 1;
#else
                          radlog(L_WARN,
                                 _("%s:%d: guile statement ignored: radiusd compiled without guile support"),
                                 filename, line_num);
#endif
                  }
                ;

guile_list      : guile_def
                | guile_list guile_def
                ;

guile_def       : T_LOAD_PATH value EOL
                  {
#ifdef USE_SERVER_GUILE
                          if ($2.type != AT_STRING) {
                                  radlog(L_ERR, 
                                         _("%s:%d: wrong datatype (should be string)"),
                                         filename, line_num);
                          } else
                                  scheme_add_load_path($2.v.string);
#endif
                  }
                | T_LOAD value EOL
                  {
#ifdef USE_SERVER_GUILE
                          if ($2.type != AT_STRING) {
                                  radlog(L_ERR, 
                                         _("%s:%d: wrong datatype (should be string)"),
                                         filename, line_num);
                          } else {
                                  scheme_load($2.v.string);
                          }
#endif
                  }
                | T_SEVERITY value EOL
                  {
                          if ($1 == L_DEBUG) {
#ifdef USE_SERVER_GUILE
                                  int dbg;
                                  asgn(&dbg, &$2, AT_BOOL, 0);
                                  scheme_debug(dbg);
#endif
                          } else {
                                  yyerror("syntax error");
                          }
                  }  
                ;


       /* Message definitions */

message_stmt    : T_MESSAGE '{' message_list '}'
                ;

message_list    : message_line
                | message_list message_line
                | message_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

message_line    : T_MESGDEF value EOL
                  {
                          asgn(&message_text[$1], &$2, AT_STRING, 0);
                  }
                | T_EXPWARNING value EOL
                  {
                          asgn(&message_text[MSG_PASSWORD_EXPIRE_WARNING], &$2, AT_STRING, 0);
                  }
                ;

       /* Obsolete syntax: for compatibility with 0.95 and earlier */ 
obs_option_list : obs_option_string
                | obs_option_list ',' obs_option_string
                  {
                          $$ = $1 | $3;
                  }
                ;

obs_option_string: T_STRING
                  {
                          if (strcmp($1, "pid") == 0)
                                  $$ = LO_PID;
                          else if (strcmp($1, "cons") == 0)
                                  $$ = LO_CONS;
                          else if (strcmp($1, "level") == 0)
                                  $$ = LO_PRI;
                          else
                                  $$ = 0;
                  }
                ;

        /* cntl statement */
cntl_stmt       : cntl '{' cntl_list '}'
                ;

cntl            : T_CNTL
                  {
                          obsolete("cntl", 1);
                  }
                ;

cntl_list       : cntl_line
                | cntl_list cntl_line
                | cntl_list error errmark
                  {
                          yyclearin; yyerrok;
                  }
                ;

cntl_line       : /* empty */ EOL
                | cntl_def EOL
                ;

cntl_def        : T_PORT value
                ;

notify_stmt     : T_NOTIFY '{' notify_list '}'
                  {
                          obsolete("notify", 1);
                  }
                | T_NOTIFY T_BOOL
                  {
                          obsolete("notify", 1);
                  }
                ;

notify_list     : notify_line
                | notify_list notify_line
                | notify_list error errmark
                  {
                          yyclearin;
                          yyerrok;
                  }
                ;

notify_line     : /* empty */ EOL
                | notify_def EOL
                ;

notify_def      : T_HOST value
                | T_PORT value
                | T_RETRY value
                | T_DELAY value
                ;

%%
           
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
                int keep_line = line_num;

                curp += 2;
                do {
                        while (*curp != '*') {
                                if (*curp == 0) {
                                        radlog(L_ERR, 
                                               _("%s:%d: unexpected EOF in comment started at line %d"),
                                                filename, line_num, keep_line);
                                        return 0;
                                } else if (*curp == '\n')
                                        line_num++;
                                ++curp;
                        }
                } while (*++curp != '/');
                ++curp;
                goto again;
        }

        if (*curp == 0)
                return 0;
        
        if (isalpha(*curp)) {
                copy_alpha();
                return expect_string ? T_STRING : keyword();
        }

        if (*curp == '\"') {
                copy_string();
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
                return EOL;
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
                        filename, line_num);
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
                        line_num++;
                curp++;
        }
}

void
skipline()
{
        while (*curp && *curp != '\n')
                curp++;
}

void
skipstmt()
{
        int c;
        while ((c = yylex()) != 0 && c != EOL)
                ;
}

int
isword(c)
        int c;
{
        return isalnum(c) || c == '_' || c == '-';
}

void
copy_alpha()
{
        char * p = yylval.string;
        
        do {
                if (p >= yylval.string + sizeof(yylval.string)) {
                        radlog(L_ERR, _("%s:%d: token too long"),
                            filename, line_num);
                        break;
                }
                *p++ = *curp++;
        } while (*curp && isword(*curp));
        *p = 0;
}

void
copy_string()
{
        char * p = yylval.string;
        int quote = *curp++;

        while (*curp) {
                if (*curp == quote) {
                        curp++;
                        break;
                }
                if (p >= yylval.string + sizeof(yylval.string)) {
                        radlog(L_ERR, _("%s:%d: token too long"),
                            filename, line_num);
                        break;
                }
                *p++ = *curp++;
        } 
        *p = 0;
}

int
copy_digit()
{
        int dot = 0;
        char *p = yylval.string;

        if (*curp == '0') {
                if (curp[1] == 'x' || curp[1] == 'X') {
                        *p++ = *curp++;
                        *p++ = *curp++;
                }
        }
        
        do {
                if (p >= yylval.string + sizeof(yylval.string)) {
                        radlog(L_ERR, _("%s:%d: token too long"),
                            filename, line_num);
                        break;
                }
                if ((*p++ = *curp++) == '.')
                        dot++;
        } while (*curp && (isdigit(*curp) || *curp == '.'));
        *p = 0;
        return dot;
}

int
get_config()
{
        struct stat st;
        int fd;
        extern int yydebug;
        Channel *mark;
        
        filename = mkfilename(radius_dir, RADIUS_CONFIG);
        if (stat(filename, &st)) {
                radlog(L_ERR|L_PERROR, _("can't stat `%s'"), filename);
                efree(filename);
                return -1;
        }
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                if (errno != ENOENT)
                        radlog(L_ERR|L_PERROR, 
                                _("can't open config file `%s'"), filename);
                efree(filename);
                return -1;
        }
        buffer = emalloc(st.st_size+1);
        
        read(fd, buffer, st.st_size);
        buffer[st.st_size] = 0;
        close(fd);
        curp = buffer;

        
#ifdef USE_SNMP
        snmp_free_communities();
        snmp_free_acl();
#endif

        radlog(L_INFO, _("reading %s"), filename);
        line_num = 1;

        if (strncmp(curp, "#debug", 6) == 0) {
/* Note: can't check YYDEBUG here, because some yaccs (namely, sun's)
 *       define YYDEBUG after including code block
 */     
                yydebug = 1;
                debug_config = 1;
        } else {
                yydebug = 0;
                debug_config = 0;
        }

        mark = log_mark();
        
        /* Parse configuration */
        yyparse();

        /* Clean up the things */
        efree(filename);
        efree(buffer);
        log_release(mark);
        
#ifdef USE_SNMP
        free_netlist();
#endif
#ifdef USE_SERVER_GUILE
        scheme_end_reconfig();
#endif
        first_time = 0;
        radlog(L_INFO, _("ready"));
        return 0;
}       

void
asgn(base, value, type, once)
        void *base;
        Value *value;
        int type;
        int once;
{
        struct servent *s;
        UINT4 ipaddr;
        
        switch (type) {
        case AT_PORT:
                switch (value->type) {
                case AT_INT:
                        type = AT_INT;
                        break;
                case AT_STRING:
                          s = getservbyname(value->v.string, "udp");
                          if (s) 
                                  value->v.number = ntohs(s->s_port);
                          else {
                                  radlog(L_ERR, 
                                         _("%s:%d: no such service: %s"),
                                         filename, line_num,
                                         value->v.string);
                                  return;
                          }
                          type = value->type = AT_INT;
                          break;
                default:
                        break;
                }
                break;
                        
        case AT_IPADDR:
                switch (value->type) {
                case AT_IPADDR:
                        break;
                case AT_INT:
                        type = AT_IPADDR;
                        break;
                case AT_STRING:
                        ipaddr = ip_gethostaddr(value->v.string);
                        if (ipaddr == 0) {
                                radlog(L_ERR, 
                                       _("%s:%d: unknown host: %s"),
                                       filename, line_num,
                                       value->v.string);
                        }
                        value->v.ipaddr = ipaddr;
                        value->type = AT_IPADDR;
                        break;
                default:
                        break;
                }
        }
        
        if (type != value->type) {
                radlog(L_ERR, 
                       _("%s:%d: wrong datatype (should be %s)"),
                       filename, line_num, typestr[type]);
                return;
        }

#define check_once(c) \
        if (once && !first_time && (c))\
                schedule_restart();
        
        switch (type) {
        case AT_INT:
                check_once(*(int*) base != value->v.number);
                *(int*) base = value->v.number;
                break;
        case AT_STRING:
                check_once(*(char**)base == NULL ||
                           strcmp(*(char**)base, value->v.string));
                replace_string((char**)base, value->v.string);
                break;
        case AT_IPADDR:
                check_once(*(UINT4*) base != value->v.ipaddr);
                *(UINT4*) base = value->v.ipaddr;
                break;
        case AT_BOOL:
                check_once(*(int*) base != value->v.bool);
                *(int*) base = value->v.bool;
                break;
        default:
                radlog(L_CRIT,
                       _("INTERNAL ERROR at %s:%d: unknown datatype %d"),
                       __FILE__, __LINE__, type);
        }
}

#ifdef USE_SNMP

char *
ident_string(str)
        char *str;
{

        return estrdup(str);
}

void
add_netlist(name, list)
        char *name;
        ACL *list;
{
        Netlist *p = emalloc(sizeof(*p));
        p->next = netlist;
        p->name = estrdup(name);
        p->acl = list;
        netlist = p;
}

void
free_netlist()
{
        Netlist *p, *next;

        for (p = netlist; p; ) {
                next = p->next;
                free_acl(p->acl);
                efree(p->name);
                efree(p);
                p = next;
        }
        netlist = NULL;
}

ACL *
find_netlist(name)
        char *name;
{
        Netlist *p;

        for (p = netlist; p; p = p->next)
                if (strcmp(p->name, name) == 0) 
                        return p->acl;

        return NULL;
}

#endif

int
yyerror(s)
        char *s;
{
        radlog(L_ERR, "%s:%d: %s", filename, line_num, s);
}
                
void
obsolete(stmt, ign)
        char *stmt;
        int ign;
{
        char *expl = ign ? "Statement has no effect." : "";
        radlog(L_WARN,
               _("%s:%d: `%s' is obsolete. %s"),
               filename, line_num, stmt, expl);
}

