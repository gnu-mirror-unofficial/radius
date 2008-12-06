/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2007,2008 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef _gnu_radsql_h
#define _gnu_radsql_h

#ifdef HAVE_LIBLTDL
# define DECL_SQL_DISPATCH_TAB(mod) \
  SQL_DISPATCH_TAB GRAD_DL_EXPORT(mod,dispatch_tab)
#else
# define __s_cat2__(a,b) a ## b 
# define DECL_SQL_DISPATCH_TAB(mod) \
  SQL_DISPATCH_TAB __s_cat2__(mod,_dispatch_tab)
#endif

#ifdef USE_SQL

# define SQL_AUTH     0
# define SQL_ACCT     1
# define SQL_NSERVICE 2

# define SQL_CACHE_SIZE 16
typedef char **SQL_TUPLE;

enum radius_sql_query {
	auth_query,
	group_query,
	acct_start_query,
        acct_stop_query,
        acct_nasup_query,
        acct_nasdown_query,
        acct_keepalive_query,
        check_attr_query,
        reply_attr_query,
	mlc_user_query,
	mlc_realm_query,
	mlc_stop_query,
	auth_success_query,
	auth_failure_query,
	num_radius_sql_query
};

typedef struct {
        int      interface;
        char     *server;
        int      port;
        char     *login;
        char     *password;
        char     *acct_db;
        char     *auth_db;
	char     *query[num_radius_sql_query];
        int      keepopen;
        time_t   idle_timeout;
        int      active[SQL_NSERVICE];
} SQL_cfg;

typedef struct {
	char *query;
	size_t ntuples;
	size_t nfields;
	SQL_TUPLE *tuple;
} SQL_RESULT;

struct sql_connection {
	SQL_cfg *cfg;
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

/* Dispatcher routines */
void disp_init();
int disp_sql_interface_index(char *name);
int disp_sql_reconnect(int interface, int conn_type, struct sql_connection *conn);
void disp_sql_disconnect(struct sql_connection *conn);
int disp_sql_query(struct sql_connection *conn, const char *query,
		   int *report_cnt);
char *disp_sql_getpwd(struct sql_connection *conn, const char *query);
void *disp_sql_exec(struct sql_connection *conn, const char *query);
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
        int (*query)(struct sql_connection *, const char *query,
		     int *report_cnt);
        char *(*getpwd)(struct sql_connection *, const char *query);
        void *(*exec_query)(struct sql_connection *conn, const char *query);
        char *(*column)(void *data, size_t ncol);
        int  (*next_tuple)(struct sql_connection *conn, void *data);
        void (*free)(struct sql_connection *conn, void *data);
	int (*n_tuples)(struct sql_connection *conn, void *data, size_t *np);
	int (*n_columns)(struct sql_connection *conn, void *data, size_t *np);
} SQL_DISPATCH_TAB;

#endif
#endif
