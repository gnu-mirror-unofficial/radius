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

typedef unsigned long qid_t; /* queue identifier */

#ifdef USE_SQL

#ifndef RAD_MYSQL_PORT
# define RAD_MYSQL_PORT                 3306
#endif

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
	char     *server;
	int      port;
	char     *login;
	char     *password;
	char     *acct_db;
	char     *auth_db;
	char     *auth_query;
	char     *acct_start_query;
	char     *acct_stop_query;
	char     *acct_nasdown_query;
	BUFFER   buf;
	int      keepopen;
	time_t   idle_timeout;
	unsigned max_connections[SQL_NSERVICE];
	int      active[SQL_NSERVICE];
#define doauth   active[SQL_AUTH]
#define doacct   active[SQL_ACCT]
} SQL_cfg;

extern SQL_cfg sql_cfg;

int rad_sql_init();
void rad_sql_acct(AUTH_REQ *req);
int rad_sql_pass(AUTH_REQ *req, char *passwd);
void rad_sql_check_connect(int type);
void rad_sql_need_reconnect(int type);
int rad_sql_setup(int type, qid_t qid);
void rad_sql_cleanup(int type, qid_t qid);

/* Lower level routines: */
void rad_sql_connect(int type);
int rad_sql_reconnect(int type, struct sql_connection *);	
int rad_sql_query(struct sql_connection *, char *query, int *report_cnt);
char * rad_sql_getpwd(struct sql_connection *, char *query);

#else

# define rad_sql_check_connect(a)
# define rad_sql_setup NULL
# define rad_sql_cleanup NULL

#endif
