/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.*/

typedef unsigned long qid_t; /* queue identifier */

#define SQLT_NONE     0
#define SQLT_MYSQL    1
#define SQLT_POSTGRES 2
#define SQLT_ODBC     3
#define SQLT_MAX      4

#ifdef USE_SQL

#define SQL_AUTH     0
#define SQL_ACCT     1
#define SQL_NSERVICE 2


struct sql_connection {
	struct sql_connection *next;
	int    type;
	qid_t  qid;
	int    connected;
	time_t last_used;
	void   *data;      /* connection - specific data */
};

typedef struct {
	int      interface;
	char     *server;
	int      port;
	char     *login;
	char     *password;
	char     *acct_db;
	char     *auth_db;
	char     *auth_query;
	char     *group_query;
	char     *acct_start_query;
	char     *acct_stop_query;
	char     *acct_nasup_query;
	char     *acct_nasdown_query;
	char     *acct_keepalive_query;
	char     *check_attr_query;
	char     *reply_attr_query;
	int      keepopen;
	time_t   idle_timeout;
	unsigned max_connections[SQL_NSERVICE];
	int      active[SQL_NSERVICE];
#define doauth   active[SQL_AUTH]
#define doacct   active[SQL_ACCT]
} SQL_cfg;

extern SQL_cfg sql_cfg;

int rad_sql_init();
void rad_sql_acct(RADIUS_REQ *req);
char *rad_sql_pass(RADIUS_REQ *req, char *data);
void rad_sql_check_connect(int type);
void rad_sql_need_reconnect(int type);
int rad_sql_setup(int type, qid_t qid);
void rad_sql_cleanup(int type, qid_t qid);
int rad_sql_checkgroup(RADIUS_REQ *req, char *groupname);
int rad_sql_check_attr_query(RADIUS_REQ *req, VALUE_PAIR **check_pairs);
int rad_sql_reply_attr_query(RADIUS_REQ *req, VALUE_PAIR **reply_pairs);
void rad_sql_shutdown();
int disp_sql_interface_index(char *name);

/* Dispatcher routines */
int disp_sql_reconnect(int interface, int conn_type, struct sql_connection *);
void disp_sql_disconnect(int interface, struct sql_connection *);
int disp_sql_query(int interface, struct sql_connection *,
		   char *query, int *report_cnt);
char * disp_sql_getpwd(int interface, struct sql_connection *, char *query);
void * disp_sql_exec(int interface, struct sql_connection *conn, char *query);
char * disp_sql_column(int interface, void *data, int ncol);
int disp_sql_next_tuple(int interface, struct sql_connection *conn, void *data);
void disp_sql_free(int interface, struct sql_connection *conn, void *data);

typedef struct {
	char *name;
	int port;
	int (*reconnect)(int type, struct sql_connection *);
	void (*disconnect)(struct sql_connection *conn);
	int (*query)(struct sql_connection *, char *query, int *report_cnt);
	char *(*getpwd)(struct sql_connection *, char *query);
	void *(*exec_query)(struct sql_connection *conn, char *query);
	char *(*column)(void *data, int ncol);
	int  (*next_tuple)(struct sql_connection *conn, void *data);
	void (*free)(struct sql_connection *conn, void *data);
} SQL_DISPATCH_TAB;

#ifdef USE_SQL_MYSQL
extern SQL_DISPATCH_TAB mysql_dispatch_tab[];
#else
#define mysql_dispatch_tab NULL
#endif
#ifdef USE_SQL_POSTGRES
extern SQL_DISPATCH_TAB postgres_dispatch_tab[];
#else
#define postgres_dispatch_tab NULL
#endif
#ifdef USE_SQL_ODBC
extern SQL_DISPATCH_TAB odbc_dispatch_tab[];
#else
#define odbc_dispatch_tab NULL
#endif

#else

# define rad_sql_check_connect(a)
# define rad_sql_setup NULL
# define rad_sql_cleanup NULL
# define rad_sql_shutdown()
# define rad_sql_idle_check()

#endif
