/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,
   2006,2007,2008 Free Software Foundation, Inc.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>

#include <common.h>
#include <radius/radutmp.h>
#include <radsql.h>

#include <mysql/mysql.h>
#include <mysql/errmsg.h>

#define MYSQL_AUTH SQL_AUTH
#define MYSQL_ACCT SQL_ACCT

static int rad_mysql_reconnect(int type, struct sql_connection *conn);
static void rad_mysql_disconnect(struct sql_connection *conn, int drop);

/*************************************************************************
 * Function: do_mysql_query
 *
 * Purpose: Query MySQL database
 *************************************************************************/

static int 
do_mysql_query(struct sql_connection *conn, const char *query)
{
        int    ret;
        int    i;
        MYSQL *mysql;
        
        GRAD_DEBUG1(1, "called with %s", query);
                
        for (i = 0; i < 10; i++) {      /* Try it 10 Times */
                if (!conn->connected) {
                        rad_mysql_reconnect(conn->type, conn);
                        if (!conn->connected)
                                return -1;
                }
                mysql = (MYSQL*)conn->data;
                ret = mysql_query(mysql, query);
                GRAD_DEBUG1(1, "MYSQL query returned %d", ret);
                if (!ret) 
                        return ret;
                
		grad_log(GRAD_LOG_ERR, "[MYSQL] %s", mysql_error(mysql));

		if (mysql_errno(mysql) != CR_SERVER_GONE_ERROR) {
			rad_mysql_disconnect(conn, 0);
			return ret;
		}
        }
        GRAD_DEBUG(1, "FAILURE");
        grad_log(GRAD_LOG_ERR, "[MYSQL] %s", _("gave up on connect"));
        return ret;
}

/* ************************************************************************* */
/* Interface routines */
static int
rad_mysql_reconnect(int type, struct sql_connection *conn)
{
        MYSQL *mysql = NULL;
        char *dbname;

        switch (type) {
        case SQL_AUTH:
                dbname = conn->cfg->auth_db;
                break;
        case SQL_ACCT:
                dbname = conn->cfg->acct_db;
                break;
        }
        
        mysql = conn->data = grad_emalloc(sizeof(MYSQL));
        mysql_init(mysql);
	if (!mysql_real_connect(mysql, 
				conn->cfg->server, conn->cfg->login,
				conn->cfg->password, dbname, conn->cfg->port,
				NULL, 0)) {
		grad_log(GRAD_LOG_ERR,
		         _("[MYSQL] cannot connect to %s as %s: %s"),
		         conn->cfg->server,
		         conn->cfg->login,
		         mysql_error((MYSQL*)conn->data));
		grad_free(conn->data);
		conn->data = NULL;
		conn->connected = 0;
		return -1;
	}

	GRAD_DEBUG1(1, "connected to %s", conn->cfg->server);
	conn->connected++;
        return 0;
}

static void 
rad_mysql_disconnect(struct sql_connection *conn, int drop ARG_UNUSED)
{
	mysql_close(conn->data);
        grad_free(conn->data);
	conn->data = NULL;  
        conn->connected = 0;
}

static int
rad_mysql_query(struct sql_connection *conn, const char *query,
		int *return_count)
{
        if (!conn) 
                return -1;

        if (do_mysql_query(conn, query)) 
                return -1;
        
        if (return_count != NULL) 
                *return_count = mysql_affected_rows((MYSQL*)conn->data);

        return 0;
}

static char *
rad_mysql_getpwd(struct sql_connection *conn, const char *query)
{
        MYSQL_RES      *result;
        MYSQL_ROW       row;
        char *return_passwd;
        
        if (!conn)
                return NULL;

        GRAD_DEBUG1(1, "query: %s", query);

        if (do_mysql_query(conn, query))
                return NULL;

        if (!(result = mysql_store_result((MYSQL*)conn->data))) {
                grad_log(GRAD_LOG_ERR, _("[MYSQL]: can't get result"));
                return NULL;
        }
        if (mysql_num_rows(result) != 1) {
                /* user not found in database */
                mysql_free_result(result);
                return NULL;
        }
        row = mysql_fetch_row(result);

        return_passwd = grad_estrdup(row[0]);
        mysql_free_result(result);

        return return_passwd;
}

typedef struct {
        MYSQL_RES      *result;
        MYSQL_ROW       row;
} RADMYSQL_DATA;

static int
rad_mysql_n_columns(struct sql_connection *conn, void *data, size_t *np)
{
        RADMYSQL_DATA *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return -1;
	
        *np = mysql_num_fields(dp->result);
	return 0;
}

static int
rad_mysql_n_tuples(struct sql_connection *conn, void *data, size_t *np)
{
        RADMYSQL_DATA *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return -1;
	*np = mysql_num_rows(dp->result);
	return 0;
}

static void *
rad_mysql_exec(struct sql_connection *conn, const char *query)
{
        MYSQL_RES      *result;
        RADMYSQL_DATA  *data;
        int nrows;
        
        if (!conn)
                return NULL;
        
        GRAD_DEBUG1(1, "query: %s", query);
        
        if (do_mysql_query(conn, query))
                return NULL;

        if (!(result = mysql_store_result((MYSQL*)conn->data)))
                return NULL;

        nrows = mysql_num_rows(result);
        GRAD_DEBUG1(1, "got %d rows", nrows);
        if (nrows == 0) {
                mysql_free_result(result);
                return NULL;
        }

        data = grad_emalloc(sizeof(*data));
        data->result = result;
        return (void*)data;
}

static char *
rad_mysql_column(void *data, size_t ncol)
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return NULL;
        if (ncol >= mysql_num_fields(dp->result)) 
                return NULL;

        return dp->row[ncol];
}

/*ARGSUSED*/
static int
rad_mysql_next_tuple(struct sql_connection *conn, void *data)
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return 1;
        return (dp->row = mysql_fetch_row(dp->result)) == NULL;
}

/*ARGSUSED*/
static void
rad_mysql_free(struct sql_connection *conn, void *data)
{
        RADMYSQL_DATA  *dp = (RADMYSQL_DATA *) data;

        if (!data)
                return;

        mysql_free_result(dp->result);
        grad_free(dp);
}

DECL_SQL_DISPATCH_TAB(mysql) = {
        "mysql",
        3306,
        rad_mysql_reconnect,
        rad_mysql_disconnect,
        rad_mysql_query,
        rad_mysql_getpwd,
        rad_mysql_exec,
        rad_mysql_column,
        rad_mysql_next_tuple,
        rad_mysql_free,
	rad_mysql_n_tuples,
	rad_mysql_n_columns,
};

