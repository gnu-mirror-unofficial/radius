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

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <common.h>
#include <radsql.h>

#include <libpq-fe.h>

static int rad_postgres_reconnect(int type, struct sql_connection *conn);
static void rad_postgres_disconnect(struct sql_connection *conn, int drop);

/* ************************************************************************* */
/* Interface routines */
static int
rad_postgres_reconnect(int type, struct sql_connection *conn)
{
        PGconn  *pgconn;
        char *dbname;
        char portbuf[16];
        char *portstr;
        
        switch (type) {
        case SQL_AUTH:
                dbname = conn->cfg->auth_db;
                break;
        case SQL_ACCT:
                dbname = conn->cfg->acct_db;
                break;
        }

        if (conn->cfg->port == 0)
                portstr = NULL;
        else {
                portstr = portbuf;
                snprintf(portbuf, sizeof(portbuf), "%d", conn->cfg->port);
        }
                
        pgconn = PQsetdbLogin(conn->cfg->server, portstr, NULL, NULL,
                              dbname,
                              conn->cfg->login, conn->cfg->password);
        
        if (PQstatus(pgconn) == CONNECTION_BAD) {
                grad_log(GRAD_LOG_ERR,
                         _("PQconnectStart failed: %s"), 
                         PQerrorMessage(pgconn));
                PQfinish(pgconn);
                return -1;
        }

        conn->data = pgconn;
        conn->connected = 1;
        return 0;
}

static void 
rad_postgres_disconnect(struct sql_connection *conn,
			int drop /* currently unused */)
{
        if (!conn->data)
                return;
        PQfinish(conn->data);
        conn->data = NULL;
        conn->connected = 0;
}

static int
rad_postgres_query(struct sql_connection *conn, const char *query,
		   int *return_count)
{
        PGresult       *res;
        ExecStatusType stat;
        int            rc;

        if (!conn || !conn->data)
                return -1;

        GRAD_DEBUG1(1, "query: %s", query);
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                grad_log(GRAD_LOG_ERR,
                         "PQexec: %s",
                         PQerrorMessage((PGconn*)conn->data));
		if (PQstatus((PGconn*)conn->data) == CONNECTION_BAD)
			rad_postgres_disconnect(conn, 0);
                return -1;
        }
        
        stat = PQresultStatus(res);

        GRAD_DEBUG1(1, "status: %s", PQresStatus(stat));

	switch (stat) {
	case PGRES_COMMAND_OK:
                if (return_count)
                        *return_count = atoi(PQcmdTuples(res));
                rc = 0;
		break;

	case PGRES_TUPLES_OK:
		/* Oleg Gawriloff writes:

		   "Sometimes Acct-Start does not reach radiusd, whereas
		    subsequent Acct-Alive or Acct-Stop does. In this case
		    radiusd runs acct_alive_query or acct_stop_query which
		    try to update non-existing data. So, we chose to use
		    a stored procedure in these queries, such that updates
		    the record if it already exists or inserts a new record
		    otherwise. The procedure, however, returns
		    PGRES_TUPLES_OK, instead of PGRES_COMMAND_OK which
		    makes radius to bail out..."
		    
		    hence the need for this code: */
		
		if (return_count) {
			if (PQntuples(res) > 0 && PQnfields(res) > 0) 
				*return_count = atoi(PQgetvalue(res, 0, 0));
			else
				*return_count = 0;
		}
		rc = 0;
		break;

	default:
                grad_log(GRAD_LOG_ERR,
                         _("PQexec returned %s"),
                         PQresStatus(stat));
                if (stat == PGRES_FATAL_ERROR 
                    && PQstatus((PGconn*)conn->data) == CONNECTION_BAD) 
			rad_postgres_disconnect(conn, 0);
                rc = -1;
        }
        PQclear(res);
        return rc;
}

static char *
rad_postgres_getpwd(struct sql_connection *conn, const char *query)
{
        PGresult       *res;
        ExecStatusType stat;
        char           *return_passwd = NULL;
        
        if (!conn || !conn->data)
                return NULL;

        GRAD_DEBUG1(1, "query: %s", query);
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                grad_log(GRAD_LOG_ERR,
                         "PQexec: %s",
                         PQerrorMessage((PGconn*)conn->data));
		if (PQstatus((PGconn*)conn->data) == CONNECTION_BAD)
			rad_postgres_disconnect(conn, 0);
                return NULL;
        }
        
        stat = PQresultStatus(res);

        GRAD_DEBUG1(1, "status: %s", PQresStatus(stat));

        if (stat == PGRES_TUPLES_OK) {
                int ntuples = PQntuples(res);
                if (ntuples > 1 && PQnfields(res)) {
                        grad_log(GRAD_LOG_NOTICE,
			         ngettext("query returned %d tuple: %s",
				  	  "query returned %d tuples: %s",
					  ntuples),
                                 ntuples, query);
                } else if (ntuples == 1) {
                        return_passwd = grad_estrdup(PQgetvalue(res, 0, 0));
                }
        } else {
                grad_log(GRAD_LOG_ERR,
                         _("PQexec returned %s"),
                         PQresStatus(stat));
                if (stat == PGRES_FATAL_ERROR
                    && PQstatus((PGconn*)conn->data) == CONNECTION_BAD)
			rad_postgres_disconnect(conn, 0);
        }
        PQclear(res);
        return return_passwd;
}

typedef struct {
        PGresult       *res;
        int            nfields;
        int            ntuples;
        int            curtuple;
} EXEC_DATA;

static int
rad_postgres_n_columns(struct sql_connection *conn, void *data, size_t *np)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;
        if (!data)
                return -1;
	*np = edata->nfields;
	return 0;
}

static int
rad_postgres_n_tuples(struct sql_connection *conn, void *data, size_t *np)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;
        if (!data)
                return -1;
	*np = edata->ntuples;
	return 0;
}

static void *
rad_postgres_exec(struct sql_connection *conn, const char *query)
{
        PGresult       *res;
        ExecStatusType stat;
        EXEC_DATA      *data;
        
        if (!conn || !conn->data)
                return NULL;

        GRAD_DEBUG1(1, "query: %s", query);
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                grad_log(GRAD_LOG_ERR,
                         "PQexec: %s",
                         PQerrorMessage((PGconn*)conn->data));
		if (PQstatus((PGconn*)conn->data) == CONNECTION_BAD)
			rad_postgres_disconnect(conn, 0);
                return NULL;
        }
        
        stat = PQresultStatus(res);

        GRAD_DEBUG1(1, "status: %s", PQresStatus(stat));

        if (stat != PGRES_TUPLES_OK) {
                PQclear(res);
                if (stat == PGRES_FATAL_ERROR) {
			grad_log(GRAD_LOG_ERR,
			         _("PQexec returned %s"),
			         PQresStatus(stat));
			if (PQstatus((PGconn*)conn->data) == CONNECTION_BAD)
				rad_postgres_disconnect(conn, 0);
		}
                return NULL;
        }

        data = grad_emalloc(sizeof(*data));
        data->res = res;
        data->ntuples = PQntuples(res);
        data->curtuple = -1;
        data->nfields = PQnfields(res);
        return (void*)data;
}

static char *
rad_postgres_column(void *data, size_t ncol)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;
        if (!data)
                return NULL;
        if (ncol >= edata->nfields) {
                return NULL;
        }                                                       
        return PQgetvalue(edata->res, edata->curtuple, ncol);
}

/*ARGSUSED*/
static int
rad_postgres_next_tuple(struct sql_connection *conn, void *data)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;
        if (!data)
                return 1;

        if (edata->curtuple+1 >= edata->ntuples)
                return 1;
        edata->curtuple++;
        return 0;
}

/*ARGSUSED*/
static void
rad_postgres_free(struct sql_connection *conn, void *data)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return;
        
        PQclear(edata->res);
        grad_free(edata);
}

DECL_SQL_DISPATCH_TAB(postgres) = {
        "postgres",     
        5432,
        rad_postgres_reconnect,
        rad_postgres_disconnect,
        rad_postgres_query,
        rad_postgres_getpwd,
        rad_postgres_exec,
        rad_postgres_column,
        rad_postgres_next_tuple,
        rad_postgres_free,
	rad_postgres_n_tuples,
	rad_postgres_n_columns,
};

