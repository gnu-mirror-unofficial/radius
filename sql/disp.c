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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radius.h>
#include <radsql.h>

static SQL_DISPATCH_TAB *sql_dispatch_tab[] = {
        NULL,
        mysql_dispatch_tab,
        postgres_dispatch_tab,
        odbc_dispatch_tab,
};

#define NDISP sizeof(sql_dispatch_tab)/sizeof(sql_dispatch_tab[0])

int
disp_sql_interface_index(name)
        char *name;
{
        int i;

        for (i = 1; i < NDISP; i++)
                if (sql_dispatch_tab[i]
                    && strcmp(sql_dispatch_tab[i]->name, name) == 0)
                    return i;
        return 0;
}

SQL_DISPATCH_TAB *
disp_sql_entry(type)
        int type;
{
        insist(type < SQLT_MAX);
        if (type == 0) {
                for (type = 1; type < NDISP; type++)
                        if (sql_dispatch_tab[type])
                                return sql_dispatch_tab[type];
                type = 0;
        } 
        return sql_dispatch_tab[type];
}

int
disp_sql_reconnect(type, conn_type, conn)
        int type;
        int conn_type;
        struct sql_connection *conn;
{
        if (conn->connected)
                disp_sql_entry(type)->disconnect(conn);
        return disp_sql_entry(type)->reconnect(conn_type, conn);
}

void
disp_sql_disconnect(type, conn)
        int type;
        struct sql_connection *conn;
{
        disp_sql_entry(type)->disconnect(conn);
}

int
disp_sql_query(type, conn, query, report_cnt)
        int type;
        struct sql_connection *conn;
        char *query;
        int *report_cnt;
{
        return disp_sql_entry(type)->query(conn, query, report_cnt);
}

char *
disp_sql_getpwd(type, conn, query)
        int type;
        struct sql_connection *conn;
        char *query;
{
        return disp_sql_entry(type)->getpwd(conn, query);
}

void *
disp_sql_exec(type, conn, query)
        int type;
        struct sql_connection *conn;
        char *query;
{
        return disp_sql_entry(type)->exec_query(conn, query);
}

char *
disp_sql_column(type, data, ncol)
        int type;
        void *data;
        int ncol;
{
        return disp_sql_entry(type)->column(data, ncol);
}

int
disp_sql_next_tuple(type, conn, data)
        int type;
        struct sql_connection *conn;
        void *data;
{
        return disp_sql_entry(type)->next_tuple(conn, data);
}

/*ARGSUSED*/
void
disp_sql_free(type, conn, data)
        int type;
        struct sql_connection *conn;
        void *data;
{
        disp_sql_entry(type)->free(conn, data);
}
