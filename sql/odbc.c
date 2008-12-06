/* This file is part of GNU Radius.
   Copyright (C) 2001 Vlad Lungu
   Copyright (C) 2000,2001,2004,2006,2007,2008 Sergey Pozniakoff  

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.*/

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

#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>

typedef struct {
        SQLHENV         env;
        SQLHDBC         dbc;
} ODBCconn;

static void
rad_odbc_diag(SQLSMALLINT handle_type, SQLHANDLE handle, char *what)
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
        grad_log(GRAD_LOG_ERR,
                 "%s: %s %d %s",
                 what, state, nerror, message);
}

/* ************************************************************************* */
/* Interface routines */
static int
rad_odbc_reconnect(int type, struct sql_connection *conn)
{

        ODBCconn        *oconn;
        long            result;
        char            *dbname;
        char            portbuf[16];
        char            *portstr;
        
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

        oconn = grad_emalloc(sizeof(ODBCconn));
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
                            (SQLCHAR*)conn->cfg->login, SQL_NTS,
                            (SQLCHAR*)conn->cfg->password, SQL_NTS);
        if (result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO) {
                rad_odbc_diag(SQL_HANDLE_DBC, oconn->dbc,
                              "SQLConnect failed");
                return -1;
        }
        
        conn->data = oconn;
        conn->connected = 1;
        return 0;
}

static void 
rad_odbc_disconnect(struct sql_connection *conn, int drop ARG_UNUSED)
{
        ODBCconn *odata;
        if (!conn->data)
                return ;
        odata = (ODBCconn*)(conn->data);        
        SQLDisconnect(odata->dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, odata->env);
        grad_free(conn->data);
        conn->data = NULL;
        conn->connected = 0;
}

static int
rad_odbc_query(struct sql_connection *conn, const char *query,
	       int *return_count)
{
        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLINTEGER      count;

        if (!conn || !conn->data)
                return -1;

        GRAD_DEBUG1(1, "query: %s", query);
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

static char *
rad_odbc_getpwd(struct sql_connection *conn, const char *query)
{
        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLINTEGER      size;
        SQLCHAR         passwd[128];
        char           *return_passwd = NULL;
        
        if (!conn || !conn->data)
                return NULL;

        GRAD_DEBUG1(1, "query: %s", query);

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
                grad_log(GRAD_LOG_NOTICE,
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

        return_passwd = grad_estrdup(passwd);

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return return_passwd;
}

typedef struct {
        SQLHSTMT stmt;
        int   nfields;
	int   ntuples;
} EXEC_DATA;

static int
rad_odbc_n_columns(struct sql_connection *conn, void *data, size_t *np)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
		return -1;
	*np = edata->nfields;
	return 0;
}

static int
rad_odbc_n_tuples(struct sql_connection *conn, void *data, size_t *np)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
		return -1;
	*np = edata->ntuples;
	return 0;
}

static void *
rad_odbc_exec(struct sql_connection *conn, const char *query)
{

        ODBCconn        *odata;
        long            result;
        SQLHSTMT        stmt;
        SQLSMALLINT     ccount;
	SQLINTEGER      rcount;
        EXEC_DATA      *data;
        
        if (!conn || !conn->data)
                return NULL;

        GRAD_DEBUG1(1, "query: %s", query);

        odata = (ODBCconn*)conn->data;
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
        
        if (SQLNumResultCols(stmt, &ccount) != SQL_SUCCESS
	    || SQLRowCount(stmt, &rcount) != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, stmt,
                              "SQLNumResultCount");
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }

	if (rcount == 0) {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                return NULL;
        }
		
	
        data = grad_emalloc(sizeof(*data));
        data->stmt = stmt;
        data->nfields = ccount;
	data->ntuples = rcount;
        return (void*)data;
}

static char *
rad_odbc_column(void *data, size_t ncol)
{
        SQLCHAR buffer[1024];
        long result;
        SQLINTEGER      size;
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return NULL;
        if (ncol >= edata->nfields) {
                grad_log(GRAD_LOG_ERR,
                         _("too few columns returned (%d req'd)"), ncol);
                return NULL;
        }
        
        result = SQLGetData(edata->stmt,ncol+1,SQL_C_CHAR,
                            buffer, sizeof buffer, &size);       
        if (result != SQL_SUCCESS) {
                rad_odbc_diag(SQL_HANDLE_STMT, edata->stmt,
                              "SQLGetData");
                return NULL;
        }
        return grad_estrdup(buffer);
}

/*ARGSUSED*/
static int
rad_odbc_next_tuple(struct sql_connection *conn, void *data)
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
static void
rad_odbc_free(struct sql_connection *conn, void *data)
{
        EXEC_DATA *edata = (EXEC_DATA*)data;

        if (!data)
                return;
        
        SQLFreeHandle(SQL_HANDLE_STMT, edata->stmt);
        grad_free(edata);
}

DECL_SQL_DISPATCH_TAB(odbc) = {
        "odbc",     
        0,
        rad_odbc_reconnect,
        rad_odbc_disconnect,
        rad_odbc_query,
        rad_odbc_getpwd,
        rad_odbc_exec,
        rad_odbc_column,
        rad_odbc_next_tuple,
        rad_odbc_free,
	rad_odbc_n_tuples,
	rad_odbc_n_columns,
};

