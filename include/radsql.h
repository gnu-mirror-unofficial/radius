/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define SQLT_NONE     0
#define SQLT_MYSQL    1
#define SQLT_POSTGRES 2
#define SQLT_ODBC     3
#define SQLT_MAX      4

#ifdef USE_SQL

#define SQL_AUTH     0
#define SQL_ACCT     1
#define SQL_NSERVICE 2

#define SQL_CACHE_SIZE 16
typedef char **SQL_TUPLE;

typedef struct {
	char *query;
	size_t ntuples;
	size_t nfields;
	SQL_TUPLE *tuple;
} SQL_RESULT;

struct sql_connection {
	int    interface;        /* One of SQLT_ values */
        int    type;             /* One of SQL_ values */
        int    connected;        /* Connected to the database? */
        int    destroy_on_close; /* Should the connection be closed upon
				    the end of a transaction */
        time_t last_used;        /* Time it was lastly used */
        void   *data;            /* connection-specific data */
	
	SQL_RESULT *cache[SQL_CACHE_SIZE];
	size_t head;
	size_t tail;
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
        int      active[SQL_NSERVICE];
} SQL_cfg;

extern SQL_cfg sql_cfg;

void radiusd_sql_shutdown();
void radiusd_sql_clear_cache();

int rad_sql_init();
void rad_sql_acct(grad_request_t *req);
char *rad_sql_pass(grad_request_t *req, char *data);
void rad_sql_cleanup(int type, void *req);
int rad_sql_checkgroup(grad_request_t *req, char *groupname);
int rad_sql_check_attr_query(grad_request_t *req, grad_avp_t **check_pairs);
int rad_sql_reply_attr_query(grad_request_t *req, grad_avp_t **reply_pairs);

#ifdef RADIUS_SERVER_GUILE
SCM sql_exec_query(int type, char *query);
#endif

/* Dispatcher routines */
int disp_sql_interface_index(char *name);
int disp_sql_reconnect(int interface, int conn_type, struct sql_connection *conn);
void disp_sql_disconnect(struct sql_connection *conn);
int disp_sql_query(struct sql_connection *conn, char *query, int *report_cnt);
char *disp_sql_getpwd(struct sql_connection *conn, char *query);
void *disp_sql_exec(struct sql_connection *conn, char *query);
char *disp_sql_column(struct sql_connection *conn, void *data, size_t ncol);
int disp_sql_next_tuple(struct sql_connection *conn, void *data);
void disp_sql_free(struct sql_connection *conn, void *data);
int disp_sql_num_tuples(struct sql_connection *conn, void *data, size_t *np);
int disp_sql_num_columns(struct sql_connection *conn, void *data, size_t *np);

typedef struct {
        char *name;
        int port;
        int (*reconnect)(int type, struct sql_connection *);
        void (*disconnect)(struct sql_connection *conn, int drop);
        int (*query)(struct sql_connection *, char *query, int *report_cnt);
        char *(*getpwd)(struct sql_connection *, char *query);
        void *(*exec_query)(struct sql_connection *conn, char *query);
        char *(*column)(void *data, size_t ncol);
        int  (*next_tuple)(struct sql_connection *conn, void *data);
        void (*free)(struct sql_connection *conn, void *data);
	int (*n_tuples)(struct sql_connection *conn, void *data, size_t *np);
	int (*n_columns)(struct sql_connection *conn, void *data, size_t *np);
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
# define rad_sql_cleanup (void (*)(int, void *)) NULL
# define rad_sql_shutdown()
# define rad_sql_idle_check()

#endif
