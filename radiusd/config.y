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

	struct facility {
		int number;
		char string[256];
	};

	#define CT_CHANNEL 1
	#define CT_OPTIONS 2
	#define CT_LEVEL   3
	
        #define AT_ANY    0
        #define AT_INT    1
	#define AT_STRING 2
	#define AT_IPADDR 3
	#define AT_BOOL   4

	typedef struct {
		char *name;
		int type;
		void *base;
		size_t size;
	} Variable;
		
	typedef struct {
		char name[256];
		int type;
		union {
			char string[256];
			UINT4 ipaddr;
			int number;
			int bool;
		} v;
	} Asgn;

	static char *typestr[] = {
		"any",
		"numeric",
		"string",
		"IP address",
		"boolean"
	};

	static struct keyword *xlat_tab;
	
	static struct keyword syslog_facility[] = {
		"user", 	LOG_USER,
		"daemon", 	LOG_DAEMON,
		"auth", 	LOG_AUTH,
		"local0", 	LOG_LOCAL0,
		"local1", 	LOG_LOCAL1,
		"local2", 	LOG_LOCAL2,
		"local3", 	LOG_LOCAL3,
		"local4", 	LOG_LOCAL4,
		"local5", 	LOG_LOCAL5,
		"local6", 	LOG_LOCAL6,
		"local7", 	LOG_LOCAL7,
		0
	};

	struct keyword syslog_severity[] = {
		"emerg", 	LOG_EMERG,
		"alert", 	LOG_ALERT,
		"crit", 	LOG_CRIT,
		"err", 		LOG_ERR,
		"warning", 	LOG_WARNING,
		"notice", 	LOG_NOTICE,
		"info", 	LOG_INFO,
		"debug", 	LOG_DEBUG,
		0
	};
	
	struct keyword log_tab[] = {
		"auth",        		RLOG_AUTH,
		"pass",        		RLOG_AUTH_PASS,
		"failed_pass", 		RLOG_FAILED_PASS,
		"pid",         		RLOG_PID,
		0
	};

	static struct keyword loglevels[] = {
		"debug",  		L_DBG, 
		"info",   		L_INFO,
		"notice", 		L_NOTICE,
		"warning", 		L_WARN,
		"error", 		L_ERR,
		"crit",  		L_CRIT,
		"auth",  		L_AUTH,
		"crit",  		L_CRIT,
		0
	};

	static struct keyword log_options[] = {
		"cons", 		LO_CONS,
		"pid", 			LO_PID,
		"level", 		LO_LEVEL,
		0
	};
		
#ifdef USE_DBM
	struct keyword dbm_tab[] = {
		"never", 		DBM_NEVER,
		"also",  		DBM_ALSO,
		"only",  		DBM_ONLY,
		NULL
	};
#endif
	
	Variable top_vars[] = {
		"usr2delay", AT_INT,    &config.delayed_hup_wait, 0,
		"max-requests", AT_INT, &config.max_requests, 0,
		"exec-program-user", AT_STRING,
		                 &config.exec_user, sizeof(config.exec_user)-1,
		"exec-program-group", AT_STRING,
		                 &config.exec_group, sizeof(config.exec_group)-1,
		NULL
	};

#ifdef USE_NOTIFY
	Variable notify_vars[] = {
		"host",      AT_IPADDR, &notify_cfg.ipaddr,           0,
		"port",      AT_INT,    &notify_cfg.port,             0,
		"retry",     AT_INT,    &notify_cfg.retry,            0,
		"delay",     AT_INT,    &notify_cfg.timeout,          0,
                NULL,
	};
#endif

	Variable auth_vars[] = {
		"port", AT_INT, &auth_port, 0,

		"spawn", AT_BOOL,
		&request_class[R_AUTH].spawn, 0,
		
		"time-to-live", AT_INT,
		&request_class[R_AUTH].ttl, 0,

		"max-requests", AT_INT,
		&request_class[R_AUTH].max_requests, 0,

		"request-cleanup-delay", AT_INT,
		&request_class[R_AUTH].cleanup_delay, 0,

		"detail", AT_BOOL, &auth_detail, 0,
		"strip-names", AT_BOOL, &strip_names, 0,

		"checkrad-assume-logged", AT_BOOL, 
		&config.checkrad_assume_logged, 0,

		NULL
	};

	Variable acct_vars[] = {
		"port", AT_INT, &acct_port, 0,

		"spawn", AT_BOOL,
		&request_class[R_ACCT].spawn, 0,

		"time-to-live", AT_INT,
		&request_class[R_ACCT].ttl, 0,

		"max-requests", AT_INT,
		&request_class[R_ACCT].max_requests, 0,

		"request-cleanup-delay", AT_INT,
		&request_class[R_ACCT].cleanup_delay, 0,

		NULL
	};

	Variable cntl_vars[] = {
		"port", AT_INT,	&cntl_port, 0,
		NULL
	};

	Variable proxy_vars[] = {
		"max-requests", AT_INT,
		&request_class[R_PROXY].max_requests, 0,

                "request-cleanup-delay", AT_INT,
                &request_class[R_PROXY].cleanup_delay, 0,
	};
		
#ifdef USE_SNMP	
	Variable snmp_vars[] = {
		"spawn", AT_BOOL,
		&request_class[R_SNMP].spawn, 0,

		"time-to-live", AT_INT,
		&request_class[R_SNMP].ttl, 0,

		"max-requests", AT_INT,
		&request_class[R_SNMP].max_requests, 0,

                "request-cleanup-delay", AT_INT,
                &request_class[R_SNMP].cleanup_delay, 0,

		"port", AT_INT, &snmp_port, 0,
		NULL
	};
#endif
	
	extern time_t delayed_hup_wait;
	
	static char *filename;
	static char line_num;
	static char *buffer;
	static char *curp;
	static int tie_in;
	static int in_debug;
	
#ifdef USE_DBM
	static char *dbmstr[] = {
		"never",
		"only",
		"also"
	};
#endif
	
	static Channel channel;
	
	static void skipws();
	static void skipline();
	static int isword(int c);
	static void copy_alpha();
	static void copy_string();
	static int copy_digit();
	static int keyword();
	static int decode_syslog(struct keyword *tab, char *what, struct facility *value);

	Variable * find_var(Variable *var, char *name);
	void do_asgn(Variable *varlist, Asgn *asgn);

        static void print_log_mode();

#ifdef USE_SNMP
        static char * ident_string(char *);
	static void add_netlist(char *name, ACL *list);
	static void free_netlist();
     	static ACL *find_netlist(char*);
	static int str2access(char*); 
#endif

	static int yylex();
	static void putback(char *tok, int length);

	static int debug_config;
%}

%union {
	char string[256];
	char *sptr;
	int number;
	int bool;
	UINT4 ipaddr;
	Asgn asgn;
	struct {
		int severity;
	} category;
	struct facility facility;
	struct {
		int type;
		Channel * channel;
		int options;
		int level;
	} category_def;
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
%token T_NOTIFY T_USEDBM T_LOGGING T_IDENT
%token T_CATEGORY T_OPTION T_CHANNEL T_LEVEL T_SYSLOG T_FILE
%token T_DEBUG_LEVEL
%token T_HOST T_PORT
%token T_AUTH T_ACCT T_CNTL T_PROXY
%token T_SNMP T_NETWORK T_ACL T_ALLOW T_DENY T_COMMUNITY
%token <number> T_NUMBER
%token <ipaddr> T_IPADDR
%token <string> T_STRING
%token <bool> T_BOOL

%type <ipaddr> ipaddr host_asgn
%type <string> hostname channel_name
%type <ipaddr> netmask
%type <netlist> netlist
%type <acl> acl network
%type <number> port port_asgn
%type <number> dbm_mode
%type <asgn> asgn_stmt value
%type <number> severity
%type <category> category_name
%type <number> chan_option_list chan_option
%type <number> level_list level
%type <facility> facility
%type <category_def> category_list category_def

%%
                
input           : list
                | list stmt /* this allows for the absence of trailing EOL */
                ;

list            : line
                | list line
                ;

line            : /* empty */ EOL
                | stmt EOL
                | error EOL
                  {
			  tie_in = 0;
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
                ;


options_stmt    : T_OPTION '{' option_list '}'
                ;

option_list     : option
                | option_list option
                | option_list error errmark
                  {
			  yyclearin; yyerrok;
		  }
                ;

option          : asgn_stmt EOL
                  {
			  do_asgn(top_vars, &$1);
		  }
                ;

errmark         : EOL
                | '}'
                  {
			  putback("}", 1);
		  }
                ;

        /* Auth statement */
auth_stmt       : T_AUTH '{' auth_list '}'
                ;

auth_list       : asgn_stmt EOL
                  {
			  do_asgn(auth_vars, &$1);
		  }
                | auth_list asgn_stmt EOL
                  {
			  do_asgn(auth_vars, &$2);
		  }
                ;

        /* Acct statement */
acct_stmt       : T_ACCT '{' acct_list '}'
                ;

acct_list       : asgn_stmt EOL
                  {
			  do_asgn(acct_vars, &$1);
		  }
                | acct_list asgn_stmt EOL
                  {
			  do_asgn(acct_vars, &$2);
		  }
                ;

        /* cntl statement */
cntl_stmt       : T_CNTL '{' cntl_list '}'
                ;

cntl_list       : asgn_stmt EOL
                  {
			  do_asgn(cntl_vars, &$1);
		  }
                | cntl_list asgn_stmt EOL
                  {
			  do_asgn(cntl_vars, &$2);
		  }
                ;

        /* Proxy statement */
proxy_stmt      : T_PROXY '{' proxy_list '}'
                ;

proxy_list      : asgn_stmt EOL
                  {
			  do_asgn(proxy_vars, &$1);
		  }
                | proxy_list asgn_stmt EOL
                  {
			  do_asgn(proxy_vars, &$2);
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
			  tie_in = 0;
			  in_debug = 0;
			  yyclearin;
			  yyerrok;
		  }
                ;

        /* Logging control: channel definition */

channel_stmt    : T_CHANNEL channel_name '{' channel_list '}'
                  {
			  if (channel.mode == LM_UNKNOWN) {
				  radlog(L_ERR,
				      _("%s:%d: no channel mode for `%s'"), $2);
			  } else {
				  channel.name = $2;
				  register_channel(&channel);
				  if (channel.mode == LM_FILE)
					  efree(channel.id.file);
			  }
                  }
                ;

channel_name    : T_STRING
                  {
			  channel.mode = LM_UNKNOWN;
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
                | T_SYSLOG facility '.' facility EOL
                  {
			  int prio, lev;
			  prio = decode_syslog(syslog_facility,
					       "facility", &$2);
			  lev  = decode_syslog(syslog_severity,
					       "severity", &$4);
			  if (prio != -1 && lev != -1) {
				  channel.mode = LM_SYSLOG;
				  channel.id.prio = prio | lev;
			  }
                  }
                | T_OPTION chan_option_list EOL
                  {
			  channel.options = $2;
		  }
                ;

facility        : T_NUMBER
                  {
			  $$.number = $1;
			  $$.string[0] = 0;
		  }
                | T_STRING
                  {
			  $$.number = 0;
			  strcpy($$.string, $1);
		  }
                ;

	/* Logging control: category definition */

category_stmt   : T_CATEGORY category_name '{' category_list '}'
                  {
			  switch ($2.severity) {
			  case L_AUTH:
				  log_mode = $4.level;
				  print_log_mode();
				  break;
			  }
			  in_debug = 0;
			  register_category($2.severity, $4.channel);
		  }
                ;

category_name   : severity
                  {
			  $$.severity = $1;
			  /* select xlat_tab */
			  switch ($1) {
			  case L_AUTH:
				  xlat_tab = log_tab;
				  break;
			  case L_DBG:
				  xlat_tab = NULL;
				  in_debug = 1;
				  break;
			  default:
				  xlat_tab = NULL;
			  }
                  }
                ;

severity        : '*'
                  {
			  $$ = -1;
		  }
                | T_AUTH
                  {
			  $$ = L_AUTH;
		  }
                | T_STRING
                  {
			  if (($$ = xlat_keyword(loglevels, $1, -1)) == -1) {
				radlog(L_ERR,
				      _("%s:%d: unknown severity level"),
				      filename, line_num);
				YYERROR;
			  }
		  }
                ;

category_list   : category_def
                | category_list category_def
                  {
			  $$ = $1;
			  switch ($2.type) {
			  case CT_CHANNEL:
				  $$.channel = $2.channel;
				  break;
			  case CT_LEVEL:
				  $$.level |= $2.level;
			  }
		  }
                | category_list error '}'
                  {
			  tie_in = 0;
			  putback("}", 1);
			  yyclearin;
                          yyerrok;  
                  }
                ;

category_def    : T_CHANNEL T_STRING EOL
                  {
			  $$.channel = channel_lookup($2);
			  $$.level = 0;
			  if (!$$.channel) {
				  radlog(L_ERR,
					 _("%s:%d: channel `%s' not defined"),
					 filename, line_num, $2);
				  $$.type = 0;
			  } else
				  $$.type = CT_CHANNEL;
		  }
                | T_LEVEL { tie_in++; } level_list EOL
                  {
			  tie_in = 0;
			  $$.channel = NULL;
			  if (xlat_tab) {
				  $$.type = CT_LEVEL;
				  $$.level = $3;
			  } else {
				  $$.type = -1;
				  radlog(L_WARN,
					 _("%s:%d: no levels applicable for this category"),
					 filename, line_num);
			  }
		  }
		| T_DEBUG_LEVEL { tie_in++; clear_debug(); } debug_level_list EOL
                  {
			  tie_in = 0;
		  }			  
                ;

debug_level_list: debug_level
                | debug_level_list ',' debug_level
                ;

debug_level     : T_STRING
                  {
			  if (set_module_debug_level($1, -1))
				  radlog(L_WARN,
					 _("%s:%d: no such module name: %s"),
					 filename, line_num, $1);
		  }
                | T_STRING '=' T_NUMBER
                  {
			  if (set_module_debug_level($1, $3))
				  radlog(L_WARN,
					 _("%s:%d: no such module name: %s"),
					 filename, line_num, $1);
		  }
                ;

chan_option_list: chan_option
                | chan_option_list ',' chan_option
                  {
			$$ = $1 | $3;
		  }
                ;

chan_option     : T_STRING
                  {
			 if (($$ = xlat_keyword(log_options, $1, 0)) == 0)
				radlog(L_ERR, _("%s:%d: unknown option: %s"),
				       filename, line_num, $1);
                  }
                ;

	/* Logging control: level */

level_list      : level
                | level_list ',' level
                  {
			  $$ = $1 | $3;
		  }
                ;

level           : T_STRING
                  {
			  if (xlat_tab &&
			      ($$ = xlat_keyword(xlat_tab, $1, 0)) == 0)
				  radlog(L_ERR, _("%s:%d: unknown level: %s"),
				      filename, line_num, $1);
		  }
                ;

usedbm_stmt     : T_USEDBM dbm_mode
                  {
                   #ifdef USE_DBM
			  use_dbm = $2;
			  if (debug_config)
				  radlog(L_DBG, _("use dbm: %s"),
					 dbmstr[use_dbm]);
		   #else
			  radlog(L_WARN,
				 _("%s:%d: usedbm statement ignored: radiusd compiled without DBM support"),
				 filename, line_num);
                   #endif
		  }
                ;

notify_stmt     : T_NOTIFY '{' notify_list '}'
                  {
                   #ifdef USE_NOTIFY
			  char buf[DOTTED_QUAD_LEN];

			  if (debug_config)
				  radlog(L_DBG, 
					_("TTL server %s:%d %d, %d sec"),
					 ipaddr2str(buf, notify_cfg.ipaddr),
					 notify_cfg.port,
					 notify_cfg.retry,
					 notify_cfg.timeout);
		   #else
			  radlog(L_WARN,
				 _("%s:%d: notify statement ignored: radiusd compiled without notification support"),
				 filename, line_num);
                   #endif
		  }
                | T_NOTIFY T_BOOL
                  {
                   #ifdef USE_NOTIFY
			  if ($2 == 0) {
				  notify_cfg.ipaddr = notify_cfg.port = 0;
				  if (debug_config)
					  radlog(L_DBG, _("TTL service OFF"));
			  } else {
				  yyerror("syntax error: `off' expected");
			  }
                   #endif
		  }
                ;

notify_list     : notify_def
                | notify_list notify_def
                | notify_list error errmark
                  {
			  yyclearin;
                          yyerrok;
		  }
                ;

notify_def      : asgn_stmt EOL
                  {
		   #ifdef USE_NOTIFY 
			  do_asgn(notify_vars, &$1);
                   #endif
		  }
                | /* empty */ EOL
                ;


	/* DBM usage mode */
dbm_mode        : T_STRING
                  {
                   #ifdef USE_DBM
			  int n = xlat_keyword(dbm_tab, $1, -1);
			  if (n < 0) {
				  radlog(L_ERR,
					 _("%s:%d: unknown dbm mode"),
					 filename, line_num);
				  $$ = 0;
		          } else
				  $$ = n;
                   #endif
		  }
                | T_NUMBER
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

snmp_line       : snmp_def EOL
                ;

snmp_def        : /* empty */ 
                | T_IDENT T_STRING
                  {
                   #ifdef USE_SNMP
                          if (server_id)
			         efree(server_id);
                          server_id = ident_string($2);
                   #endif
                  }
                | asgn_stmt
                  {
		   #ifdef USE_SNMP
			  do_asgn(snmp_vars, &$1);
		   #endif
		  }
		| T_COMMUNITY T_STRING T_STRING
                  {
                   #ifdef USE_SNMP
			  int access;
		     
			  if (snmp_find_community($2)) {
				  radlog(L_ERR,
				      _("%s:%d: community %s already declared"),
				      filename, line_num, $2);
			  } else if ((access = str2access($3)) == -1) {
				  radlog(L_ERR,
				      _("%s:%d: invalid access mode %s"),
				      filename, line_num, $3);
			  } else {
				  snmp_add_community($2, access);
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

acl_line        : acl_def EOL
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
asgn_stmt       : T_STRING value
                  {
			  $$ = $2;
			  strncpy($$.name, $1, sizeof($$.name));
			  $$.name[sizeof($$.name)-1] = 0;
		  }
                | host_asgn
                  {
			  strcpy($$.name, "host");
			  $$.type = AT_IPADDR;
			  $$.v.ipaddr = $1;
		  }
                | port_asgn
                  {
			  strcpy($$.name, "port");
			  $$.type = AT_INT;
			  $$.v.number = $1;
		  }
                ;

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

	/* Assignments: special forms */

host_asgn       : T_HOST ipaddr
                  {
			  $$ = $2;
		  }
                ;
	
ipaddr          : T_IPADDR
                | hostname
                  {
			  if (($$ = get_ipaddr($1)) == (UINT4) 0) {
				  radlog(L_ERR, 
					 _("%s:%d: unknown host: %s"),
					 filename, line_num, $1);
			  }
		  }
                ;

hostname        : T_STRING
                | hostname '.' T_STRING
                  {
                          if (strlen($1) + strlen($3) + 2 >= sizeof($1)) {
				  radlog(L_ERR, 
					 _("%s:%d: hostname too long"),
					 filename, line_num);
				  YYERROR;
			  }
			  sprintf($$, "%s.%s", $1, $3);
                  }	
                ;

port_asgn       : T_PORT port
                  {
			  $$ = $2;
		  }
                ;

port            : T_NUMBER
                | T_STRING
                  {
			  struct servent *s;
			  s = getservbyname($1, "udp");
			  if (s) 
				  $$ = ntohs(s->s_port);
			  else {
				  radlog(L_ERR, 
                                         _("%s:%d: no such service: %s"),
					 filename, line_num, $1);
				  $$ = 0;
			  }
		  }
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
		return keyword();
	}

	if (*curp == '\"') {
		copy_string();
		return T_STRING;
	}
	
	if (isdigit(*curp)) {
		if (copy_digit()) {
			/* IP address */
			yylval.ipaddr = ipstr2long(yylval.string);
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

#ifdef USE_SNMP
static struct keyword accs[] = {
	"ro",         SNMP_RO,
	"read_only",  SNMP_RO,
	"rw",         SNMP_RW,
	"read_write", SNMP_RW,
	0
};

int
str2access(str)
	char *str;
{
	struct keyword *kw;

	for (kw = accs; kw->name; kw++)
		if (strcmp(kw->name, str) == 0)
			return kw->tok;
	return -1;
}
#endif

struct keyword keywords[] = {
	"notify", T_NOTIFY,
	"host", T_HOST,
	"port", T_PORT,
	"file", T_FILE,
	"syslog", T_SYSLOG,
	"category", T_CATEGORY,
	"channel", T_CHANNEL,
	"option", T_OPTION,
/*	"level", T_LEVEL,         Handled separately */
	"usedbm", T_USEDBM,
	"log", T_LOGGING,
	"logging", T_LOGGING,
	"snmp", T_SNMP,
        "ident", T_IDENT,
	"acl", T_ACL,
	"network", T_NETWORK,
	"allow", T_ALLOW,
	"deny", T_DENY,
	"community", T_COMMUNITY,
	"auth", T_AUTH,
	"acct", T_ACCT,
	"cntl", T_CNTL,
	"proxy", T_PROXY,
	0
};

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

	if (tie_in)
		return T_STRING;

	if (strcmp(yylval.string, "level") == 0) 
		return in_debug ? T_DEBUG_LEVEL : T_LEVEL; 
	/* First, see if this is a keyword */
        if (tok = xlat_keyword(keywords, yylval.string, 0))
	        return tok;
	if ((tok = xlat_keyword(booleans, yylval.string, -1)) != -1) {
                yylval.bool = tok;
	        return T_BOOL;
        }
	return T_STRING;
}


void
print_log_mode()
{
	struct keyword *kw;
	char buf[128];

	if (debug_config) {
		buf[0] = 0;
		for (kw = log_tab; kw->name; kw++) {
			if (log_mode & kw->tok) {
				strcat(buf, " ");
				strcat(buf, kw->name);
			}
		}
		radlog(L_DBG, "log:%s", buf);
	}
}

int
get_config()
{
	struct stat st;
	int fd;
	extern int yydebug;

	log_init();
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
#if defined(YACC_DEBUG)
		yydebug = 1;
#else
		radlog(L_WARN,
		    _("%s:%d: #debug ignored: radiusd compiled without parser debugging support"),
		    filename, line_num);
#endif
		debug_config = 1;
	} else {
#if defined(YACC_DEBUG)
		yydebug = 0;
#endif
		debug_config = 0;
	}

	yyparse();
	efree(filename);
	efree(buffer);
	log_cleanup(0);
	
#ifdef USE_SNMP
	free_netlist();
#endif

        radlog(L_INFO, _("ready"));
	return 0;
}	

Variable *
find_var(var, name)
	Variable *var;
	char *name;
{
	for (; var->name; var++)
		if (strcmp(var->name, name) == 0)
			return var;
	return NULL;
}

void
do_asgn(varlist, asgn)
	Variable *varlist;
	Asgn *asgn;
{
	Variable *var;
	int length;

	var = find_var(varlist, asgn->name);
	if (!var) {
		radlog(L_ERR, _("%s:%d: variable `%s' undefined"),
		       filename, line_num, asgn->name);
		return;
	}
	if (var->type != asgn->type) {
		radlog(L_ERR, 
                       _("%s:%d: wrong datatype for `%s' (should be %s)"),
		       filename, line_num, typestr[var->type]);
		return;
	}
	switch (var->type) {
	case AT_INT:
		*(int*) var->base = asgn->v.number;
		break;
	case AT_STRING:
		length = strlen(asgn->v.string);
		if (length > var->size) {
			radlog(L_ERR,
			       _("%s:%d: string value too long. Limit is %d"),
			       var->size);
			length = var->size-1;
		}
		memcpy(var->base, asgn->v.string, length);
		((char*)var->base)[length] = 0;
		break;
	case AT_IPADDR:
		*(UINT4*) var->base = asgn->v.ipaddr;
		break;
	case AT_BOOL:
		*(int*) var->base = asgn->v.bool;
		break;
	default:
		radlog(L_CRIT,
		       _("INTERNAL ERROR at %s:%d: unknown datatype %d, var %p"),
		       __FILE__, __LINE__, var->type, var);
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
decode_syslog(tab, what, value)
	struct keyword *tab;
	char *what;
	struct facility *value;
{
	int val;
	
	if (value->number)
		val = value->number;
	else {
		val = xlat_keyword(tab, value->string, -1);
		if (val == -1) 
			radlog(L_ERR,
			    _("%s:%d: unknown syslog %s: %s"),
			    filename, line_num, what, value->string);
	}
	return val;
}

int
yyerror(s)
	char *s;
{
	radlog(L_ERR, "%s:%d: %s", filename, line_num, s);
}
		


