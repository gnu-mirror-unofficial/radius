/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_POSTGRES_C
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <radius.h>
#include <radsql.h>

#ifdef USE_SQL_POSTGRES

#include <libpq-fe.h>

static int rad_postgres_reconnect(int type, struct sql_connection *conn);
static void rad_postgres_disconnect(struct sql_connection *conn, int drop);
static int rad_postgres_query(struct sql_connection *conn, char *query, int *return_count);
static char *rad_postgres_getpwd(struct sql_connection *conn, char *query);
static void *rad_postgres_exec(struct sql_connection *conn, char *query);
static char *rad_postgres_column(void *data, int ncol);
static int rad_postgres_next_tuple(struct sql_connection *conn, void *data);
static void rad_postgres_free(struct sql_connection *conn, void *data);

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
                dbname = sql_cfg.auth_db;
                break;
        case SQL_ACCT:
                dbname = sql_cfg.acct_db;
                break;
        }

        if (sql_cfg.port == 0)
                portstr = NULL;
        else {
                portstr = portbuf;
                snprintf(portbuf, sizeof(portbuf), "%d", sql_cfg.port);
        }
                
        pgconn = PQsetdbLogin(sql_cfg.server, portstr, NULL, NULL,
                              dbname,
                              sql_cfg.login, sql_cfg.password);
        
        if (PQstatus(pgconn) == CONNECTION_BAD) {
                radlog(L_ERR,
                       _("PQconnectStart failed: %s"), PQerrorMessage(pgconn));
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
rad_postgres_query(struct sql_connection *conn, char *query, int *return_count)
{
        PGresult       *res;
        ExecStatusType stat;
        int            rc;

        if (!conn || !conn->data)
                return -1;

        debug(1, ("query: %s", query));
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                radlog(L_ERR,
                       "PQexec: %s",
                       PQerrorMessage((PGconn*)conn->data));
                return -1;
        }
        
        stat = PQresultStatus(res);

        debug(1,
              ("status: %s",
              PQresStatus(stat)));

        if (stat == PGRES_COMMAND_OK) {
                if (return_count)
                        *return_count = atoi(PQcmdTuples(res));
                rc = 0;
        } else {
                radlog(L_ERR,
                       ("PQexec returned %s"),
                       PQresStatus(stat));
                if (stat == PGRES_FATAL_ERROR) 
			rad_postgres_disconnect(conn, 0);
                rc = -1;
        }
        PQclear(res);
        return rc;
}

static char *
rad_postgres_getpwd(struct sql_connection *conn, char *query)
{
        PGresult       *res;
        ExecStatusType stat;
        char           *return_passwd = NULL;
        
        if (!conn || !conn->data)
                return NULL;

        debug(1, ("query: %s", query));
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                radlog(L_ERR,
                       "PQexec: %s",
                       PQerrorMessage((PGconn*)conn->data));
                return NULL;
        }
        
        stat = PQresultStatus(res);

        debug(1,
              ("status: %s",
              PQresStatus(stat)));

        if (stat == PGRES_TUPLES_OK) {
                int ntuples = PQntuples(res);
                if (ntuples > 1 && PQnfields(res)) {
                        radlog(L_NOTICE,
			       ngettext("query returned %d tuple: %s",
					"query returned %d tuples: %s",
					ntuples),
                               ntuples, query);
                } else if (ntuples == 1) {
                        return_passwd = estrdup(PQgetvalue(res, 0, 0));
                }
        } else {
                radlog(L_ERR,
                       _("PQexec returned %s"),
                       PQresStatus(stat));
                if (stat == PGRES_FATAL_ERROR)
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

static void *
rad_postgres_exec(struct sql_connection *conn, char *query)
{
        PGresult       *res;
        ExecStatusType stat;
        EXEC_DATA      *data;
        
        if (!conn || !conn->data)
                return NULL;

        debug(1, ("query: %s", query));
        
        res = PQexec((PGconn*)conn->data, query);
        if (res == NULL) {
                radlog(L_ERR,
                       "PQexec: %s",
                       PQerrorMessage((PGconn*)conn->data));
                return NULL;
        }
        
        stat = PQresultStatus(res);

        debug(1,
              ("status: %s",
              PQresStatus(stat)));

        if (stat != PGRES_TUPLES_OK) {
                radlog(L_ERR,
                       _("PQexec returned %s"),
                       PQresStatus(stat));
                PQclear(res);
                if (stat == PGRES_FATAL_ERROR)
			rad_postgres_disconnect(conn, 0);
                return NULL;
        }

        data = emalloc(sizeof(*data));
        data->res = res;
        data->ntuples = PQntuples(res);
        data->curtuple = -1;
        data->nfields = PQnfields(res);
        return (void*)data;
}

static char *
rad_postgres_column(void *data, int ncol)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;
        if (!data)
                return NULL;
        if (ncol >= edata->nfields) {
                radlog(L_ERR,
                       _("too few columns returned (%d req'd)"), ncol);
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
        efree(edata);
}

SQL_DISPATCH_TAB postgres_dispatch_tab[] = {
        "postgres",     
        5432,
        rad_postgres_reconnect,
        rad_postgres_disconnect,
        rad_postgres_query,
        rad_postgres_getpwd,
        rad_postgres_exec,
        rad_postgres_column,
        rad_postgres_next_tuple,
        rad_postgres_free
};

#endif

