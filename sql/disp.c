/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

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
disp_sql_interface_index(char *name)
{
        int i;

        for (i = 1; i < NDISP; i++)
                if (sql_dispatch_tab[i]
                    && strcmp(sql_dispatch_tab[i]->name, name) == 0)
                    return i;
        return 0;
}

SQL_DISPATCH_TAB *
disp_sql_entry(int type)
{
        grad_insist(type < SQLT_MAX);
        if (type == 0) {
                for (type = 1; type < NDISP; type++)
                        if (sql_dispatch_tab[type])
                                return sql_dispatch_tab[type];
                type = 0;
        } 
        return sql_dispatch_tab[type];
}

int
disp_sql_reconnect(int interface, int conn_type, struct sql_connection *conn)
{
	if (!conn)
		return -1;
        if (conn->connected)
                disp_sql_entry(conn->interface)->disconnect(conn, 0);
	conn->interface = interface;
        return disp_sql_entry(conn->interface)->reconnect(conn_type, conn);
}

void
disp_sql_drop(struct sql_connection *conn)
{
	if (conn && conn->connected)
		disp_sql_entry(conn->interface)->disconnect(conn, 1);
}

void
disp_sql_disconnect(struct sql_connection *conn)
{
	if (conn && conn->connected)
		disp_sql_entry(conn->interface)->disconnect(conn, 0);
}

int
disp_sql_query(struct sql_connection *conn, char *query, int *report_cnt)
{
	int rc;

	if (!conn)
		return -1;
	rc = disp_sql_entry(conn->interface)->query(conn, query, report_cnt);
	if (rc) 
		grad_log(L_ERR, "%s: %s", _("Failed query was"), query);
	return rc;
}

char *
disp_sql_getpwd(struct sql_connection *conn, char *query)
{
	if (!conn)
		return NULL;
        return disp_sql_entry(conn->interface)->getpwd(conn, query);
}

void *
disp_sql_exec(struct sql_connection *conn, char *query)
{
        return disp_sql_entry(conn->interface)->exec_query(conn, query);
}

char *
disp_sql_column(struct sql_connection *conn, void *data, size_t ncol)
{
        return disp_sql_entry(conn->interface)->column(data, ncol);
}

int
disp_sql_next_tuple(struct sql_connection *conn, void *data)
{
	if (!conn)
		return -1;
        return disp_sql_entry(conn->interface)->next_tuple(conn, data);
}

/*ARGSUSED*/
void
disp_sql_free(struct sql_connection *conn, void *data)
{
	if (conn)
		disp_sql_entry(conn->interface)->free(conn, data);
}

int
disp_sql_num_tuples(struct sql_connection *conn, void *data, size_t *np)
{
	if (conn)
		return disp_sql_entry(conn->interface)->n_tuples(conn,
								 data, np);
	return -1;
}

int
disp_sql_num_columns(struct sql_connection *conn, void *data, size_t *np)
{
	if (conn)
		return disp_sql_entry(conn->interface)->n_columns(conn,
								  data, np);
	return 0;
}


