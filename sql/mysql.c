/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
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

#define RADIUS_MODULE_MYSQL_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef lint
static char rcsid[] =
 "@(#) $Id$";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>

#include <sysdep.h>
#include <radius.h>
#include <radutmp.h>
#include <radsql.h>

#ifdef USE_SQL_MYSQL

#include <mysql/mysql.h>

#define MYSQL_AUTH SQL_AUTH
#define MYSQL_ACCT SQL_ACCT

static int  do_mysql_query(struct sql_connection *conn, char *query);
static int rad_mysql_reconnect(int type, struct sql_connection *conn);
static void rad_mysql_disconnect(struct sql_connection *conn);
static int rad_mysql_query(struct sql_connection *conn, char *query, int *return_count);
static char *rad_mysql_getpwd(struct sql_connection *conn, char *query);
static void *rad_mysql_exec(struct sql_connection *conn, char *query);
static char *rad_mysql_column(void *data, int ncol);
static int rad_mysql_next_tuple(struct sql_connection *conn, void *data);
static void rad_mysql_free(struct sql_connection *conn, void *data);

/*************************************************************************
 * Function: do_mysql_query
 *
 * Purpose: Query MySQL database
 *************************************************************************/

static int 
do_mysql_query(conn, query)
        struct sql_connection *conn;
        char *query;
{
        int    ret;
        int    i;
        MYSQL *mysql;
        
        debug(1, ("called with %s", query));
                
        for (i = 0; i < 10; i++) {      /* Try it 10 Times */
                if (!conn->connected) {
                        rad_mysql_reconnect(conn->type, conn);
                        if (!conn->connected)
                                return -1;
                }
                mysql = (MYSQL*)conn->data;
                ret = mysql_query(mysql, query);
                debug(1, ("MYSQL query returned %d", ret));
                if (!ret) 
                        return ret;
                
		radlog(L_ERR, "[MYSQL] %s", mysql_error(mysql));

		rad_mysql_disconnect(conn);
		return ret;
        }
        debug(1,("FAILURE"));
        radlog(L_ERR, "[MYSQL] %s", _("gave up on connect"));
        return ret;
}

/* ************************************************************************* */
/* Interface routines */
int
rad_mysql_reconnect(type, conn)
        int    type;
        struct sql_connection *conn;
{
        MYSQL *mysql = NULL;
        char *dbname;

        switch (type) {
        case SQL_AUTH:
                dbname = sql_cfg.auth_db;
                break;
        case SQL_ACCT:
                dbname = sql_cfg.acct_db;
                break;
        }
        
        mysql = conn->data = alloc_entry(sizeof(MYSQL));
        mysql_init(mysql);
	if (!mysql_real_connect(mysql, 
				sql_cfg.server, sql_cfg.login,
				sql_cfg.password, dbname, sql_cfg.port,
				NULL, 0)) {
		radlog(L_ERR,
		       _("[MYSQL] cannot connect to %s as %s: %s"),
		       sql_cfg.server,
		       sql_cfg.login,
		       mysql_error((MYSQL*)conn->data));
		free_entry(conn->data);
		conn->data = NULL;
		conn->connected = 0;
		return -1;
	}

	debug(1, ("connected to %s", sql_cfg.server));
	conn->connected++;
        return 0;
}

void 
rad_mysql_disconnect(conn)
        struct sql_connection *conn;
{
        mysql_close(conn->data);
        free_entry(conn->data);
        conn->connected = 0;
}

int
rad_mysql_query(conn, query, return_count)
        struct sql_connection *conn;
        char *query;
        int *return_count;
{
        if (!conn) 
                return -1;

        if (do_mysql_query(conn, query)) 
                return -1;
        
        if (return_count != NULL) 
                *return_count = mysql_affected_rows((MYSQL*)conn->data);

        return 0;
}

char *
rad_mysql_getpwd(conn, query)
        struct sql_connection *conn;
        char *query;
{
        MYSQL_RES      *result;
        MYSQL_ROW       row;
        char *return_passwd;
        
        if (!conn)
                return NULL;

        debug(1, ("query: %s", query));

        if (do_mysql_query(conn, query))
                return NULL;

        if (!(result = mysql_store_result((MYSQL*)conn->data))) {
                radlog(L_ERR, _("[MYSQL]: can't get result"));
                return NULL;
        }
        if (mysql_num_rows(result) != 1) {
                /* user not found in database */
                mysql_free_result(result);
                return NULL;
        }
        row = mysql_fetch_row(result);

        return_passwd = estrdup(row[0]);
        mysql_free_result(result);

        return return_passwd;
}

typedef struct {
        MYSQL_RES      *result;
        MYSQL_ROW       row;
} RADMYSQL_DATA;

void *
rad_mysql_exec(conn, query)
        struct sql_connection *conn;
        char *query;
{
        MYSQL_RES      *result;
        RADMYSQL_DATA  *data;
        int nrows;
        
        if (!conn)
                return NULL;
        
        debug(1, ("query: %s", query));
        
        if (do_mysql_query(conn, query))
                return NULL;

        if (!(result = mysql_store_result((MYSQL*)conn->data))) {
                radlog(L_ERR, _("[MYSQL]: can't get result"));
                return NULL;
        }
        nrows = mysql_num_rows(result);
        debug(1, ("got %d rows", nrows));
        if (nrows == 0) {
                mysql_free_result(result);
                return NULL;
        }

        data = emalloc(sizeof(*data));
        data->result = result;
        return (void*)data;
}

char *
rad_mysql_column(data, ncol)
        void *data;
        int ncol;
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return NULL;
        if (ncol >= mysql_num_fields(dp->result)) {
                radlog(L_ERR,
                       _("too few columns returned (%d req'd)"), ncol);
                return NULL;
        }
        return dp->row[ncol];
}

/*ARGSUSED*/
int
rad_mysql_next_tuple(conn, data)
        struct sql_connection *conn;
        void *data;
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return 1;
        return (dp->row = mysql_fetch_row(dp->result)) == NULL;
}

/*ARGSUSED*/
void
rad_mysql_free(conn, data)
        struct sql_connection *conn;
        void *data;
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return;

        mysql_free_result(dp->result);
        efree(dp);
}

SQL_DISPATCH_TAB mysql_dispatch_tab[] = {
        "mysql",
        3306,
        rad_mysql_reconnect,
        rad_mysql_disconnect,
        rad_mysql_query,
        rad_mysql_getpwd,
        rad_mysql_exec,
        rad_mysql_column,
        rad_mysql_next_tuple,
        rad_mysql_free
};

#endif /* USE_SQL_MYSQL */
