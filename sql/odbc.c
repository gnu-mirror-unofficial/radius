/* This file is part of GNU RADIUS.
   Copyright (C) 2001 Vlad Lungu
   based on postgresql.c (C) 2000,2001 Sergey Pozniakoff  

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

#define RADIUS_MODULE_ODBC_C
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef lint
static char rcsid[] =
 "@(#) $Id$" ;
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <radius.h>
#include <radsql.h>

#ifdef USE_SQL_ODBC

#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>

typedef struct {
        SQLHENV         env;
        SQLHDBC         dbc;
} ODBCconn;

static int rad_odbc_reconnect(int type, struct sql_connection *conn);
static void rad_odbc_disconnect(struct sql_connection *conn);
static int rad_odbc_query(struct sql_connection *conn, char *query, int *return_count);
static char *rad_odbc_getpwd(struct sql_connection *conn, char *query);
static void *rad_odbc_exec(struct sql_connection *conn, char *query);
static char *rad_odbc_column(void *data, int ncol);
static int rad_odbc_next_tuple(struct sql_connection *conn, void *data);
static void rad_odbc_free(struct sql_connection *conn, void *data);

void
rad_odbc_diag(handle_type, handle, what)
        SQLSMALLINT handle_type;
        SQLHANDLE handle;
        char *what;
{
        char state[16];
        SQLINTEGER nerror;
        SQLCHAR message[1024];
        SQLSMALLINT msglen;
        
        SQLGetDiagRec(handle_type,
                      handle,
                      1,
                      state,
                      &nerror,
                      message, sizeof message, &msglen);
        radlog(L_ERR,
               "%s: %s %d %s",
               what, state, nerror, message);
}

/* ************************************************************************* */
/* Interface routines */
int
rad_odbc_reconnect(type, conn)
        int    type;
        struct sql_connection *conn;
{

        ODBCconn        *oconn;
        long            result;
        char            *dbname;
        char            portbuf[16];
        char            *portstr;
        
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

        oconn = emalloc(sizeof(ODBCconn));
        result = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &oconn->env);
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_ENV, oconn->env,
                              "SQLAllocHandle failed");
                return -1;
        }
        result = SQLSetEnvAttr(oconn->env,
                               SQL_ATTR_ODBC_VERSION,
                               (void*)SQL_OV_ODBC3, 0);
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_ENV, oconn->dbc,
                              "SQLSetEnvAttr failed");
                return -1;
        }
        result = SQLAllocHandle(SQL_HANDLE_DBC, oconn->env, &oconn->dbc);
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_DBC, oconn->dbc,
                              "SQLAllocHandle failed");
                return -1;
        }
        result = SQLConnect(oconn->dbc,
                            (SQLCHAR*)dbname, SQL_NTS,
                            (SQLCHAR*)sql_cfg.login, SQL_NTS,
                            (SQLCHAR*)sql_cfg.password, SQL_NTS);
        if (result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO) {
                rad_odbc_diag(SQL_HANDLE_DBC, oconn->dbc,
                              "SQLConnect failed");
                return -1;
        }
        
        conn->data = oconn;
        conn->connected = 1;
        return 0;
}

void 
rad_odbc_disconnect(conn)
        struct sql_connection *conn;
{
        ODBCconn *odata;
        if (!conn->data)
                return ;
        odata = (ODBCconn*)(conn->data);        
        SQLDisconnect(odata->dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, odata->env);
        efree(conn->data);
        conn->data = NULL;
        conn->connected = 0;
}

int
rad_odbc_query(conn, query, return_count)
        struct sql_connection *conn;
        char *query;
        int *return_count;
{
        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLINTEGER      count;

        if (!conn || !conn->data)
                return -1;

        debug(1, ("query: %s", query));
        odata = (ODBCconn*)(conn->data);
        result = SQLAllocHandle(SQL_HANDLE_STMT,odata->dbc,&stmt);      
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_DBC, odata->dbc,
                              "SQLAllocHandle");
                return -1;
        }

        result = SQLExecDirect(stmt, query, SQL_NTS);   
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLExecDirect: %s %d %s");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return -1;
        }
        result = SQLRowCount(stmt, &count);     
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLRowCount");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return -1;
        }
        if (return_count)
                *return_count = count;
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return 0;
}

char *
rad_odbc_getpwd(conn, query)
        struct sql_connection *conn;
        char *query;
{
        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLINTEGER      size;
        SQLCHAR         passwd[128];
        char           *return_passwd = NULL;
        
        if (!conn || !conn->data)
                return NULL;

        debug(1, ("query: %s", query));

        odata = (ODBCconn*)(conn->data);
        result = SQLAllocHandle(SQL_HANDLE_STMT, odata->dbc, &stmt);    
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_DBC, odata->dbc,
                              "SQLAllocHandle");
                return NULL;
        }

        result = SQLExecDirect(stmt, query, SQL_NTS);   
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLExecDirect");
                return NULL;
        }


        result = SQLFetch(stmt);
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLFetch");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

        SQLGetData(stmt, 1, SQL_C_CHAR, passwd, 128, &size);    
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLGetData");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

        result = SQLFetch(stmt);

        if (result == SQL_SUCCESS) {
                radlog(L_NOTICE,
               _("query returned more tuples: %s"),
                query);
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

        if (result != SQL_NO_DATA) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLFetch");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

        return_passwd = estrdup(passwd);

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return return_passwd;
}

typedef struct {
        void            *stmt;
        int             nfields;
} EXEC_DATA;

void *
rad_odbc_exec(conn, query)
        struct sql_connection *conn;
        char *query;
{

        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLSMALLINT     ccount;
        EXEC_DATA      *data;
        
        if (!conn || !conn->data)
                return NULL;

        debug(1, ("query: %s", query));

        odata = (ODBCconn*)(conn->data);
        result = SQLAllocHandle(SQL_HANDLE_STMT,odata->dbc, &stmt);     
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_DBC, odata->dbc,
                              "SQLAllocHandle");
                return NULL;
        }

        result = SQLExecDirect(stmt, query, SQL_NTS);   
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLExecDirect");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }
        
        result = SQLNumResultCols(stmt, &ccount);       
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLNumResultCount");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

        data = emalloc(sizeof(*data));
        data->stmt = stmt;
        data->nfields = ccount;
        return (void*)data;
}

char *
rad_odbc_column(data, ncol)
        void *data;
        int ncol;
{
        SQLCHAR buffer[1024];
        long result;
        SQLINTEGER      size;
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return NULL;
        if (ncol >= edata->nfields) {
                radlog(L_ERR,
                       _("too few columns returned (%d req'd)"), ncol);
                return NULL;
        }
        
        SQLGetData(edata->stmt,ncol+1,SQL_C_CHAR,
                   buffer, sizeof buffer, &size);       
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, edata->stmt,
                              "SQLGetData");
                return NULL;
        }
        return estrdup(buffer);
}

/*ARGSUSED*/
int
rad_odbc_next_tuple(conn, data)
        struct sql_connection *conn;
        void *data;
{
        long result;
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return 1;

        result = SQLFetch(edata->stmt);

        if (result == SQL_SUCCESS) 
                return 0;

        if (result == SQL_NO_DATA) 
                return 1;

        rad_odbc_diag(SQL_HANDLE_STMT, edata->stmt,
                      "SQLFetch");
        return 1;


}

/*ARGSUSED*/
void
rad_odbc_free(conn, data)
        struct sql_connection *conn;
        void *data;
{
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return;
        
        SQLFreeHandle(SQL_HANDLE_STMT, edata->stmt);
        efree(edata);
}

SQL_DISPATCH_TAB odbc_dispatch_tab[] = {
        "odbc",     
        0,
        rad_odbc_reconnect,
        rad_odbc_disconnect,
        rad_odbc_query,
        rad_odbc_getpwd,
        rad_odbc_exec,
        rad_odbc_column,
        rad_odbc_next_tuple,
        rad_odbc_free
};

#endif

