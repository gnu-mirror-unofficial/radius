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
#define RADIUS_MODULE 16
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(USE_SQL) && defined(USE_SQL_MYSQL)

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

#include <mysql/mysql.h>

#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <radsql.h>

#define MYSQL_AUTH SQL_AUTH
#define MYSQL_ACCT SQL_ACCT


/* ************************************************************************* */
/*
 * The mysql connection code was adopted from Wim Bonis's (bonis@kiss.de)
 * accounting patch to livingston radius 2.01.
 */

/*************************************************************************
 * Function: do_mysql_query
 *
 * Purpose: Query MySQL database
 *************************************************************************/

int 
do_mysql_query(conn, query)
	struct sql_connection *conn;
	char *query;
{
	int    ret;
	int    i;
	MYSQL *mysql;
#ifdef STOP_SIGNALS
	sigset_t        set, old_set;
#endif
	
	debug(1, ("called with %s", query));
		
	for (i = 0; i < 10; i++) {	/* Try it 10 Times */
		if (!conn->connected) {
			rad_sql_reconnect(conn->type, conn);
			if (!conn->connected)
				return -1;
		}
		mysql = (MYSQL*)conn->data;
#ifdef STOP_SIGNALS
		/*
		 * Try to not catch any signals during mysql_query We need
		 * this if mysql is less than 3.20.25 or 3.21.3
		 */
		sigemptyset(&set);
		sigaddset(&set, SIGALRM);
		sigprocmask(SIG_BLOCK, &set, &old_set);
#endif
		ret = mysql_query(mysql, query);
#ifdef STOP_SIGNALS
		sigprocmask(SIG_SETMASK, &old_set, NULL);
#endif
		debug(1, ("MYSQL query returned %d", ret));
		if (!ret) {
			return ret;
		}
		
		if (!strcasecmp(mysql_error(mysql),
				"mysql server has gone away")) {
			radlog(L_ERR,
			       _("MYSQL Error (retrying %d): Cannot Query:%s"), 
			       ret, query);
			radlog(L_ERR, _("MYSQL error: %s"),
			       mysql_error(mysql));
			mysql_close(mysql);
			conn->connected = 0;
		} else {
			radlog(L_ERR, _("MYSQL Error (%d): Cannot Query:%s"),
			       ret, query);
			radlog(L_ERR, _("MYSQL error: %s"), mysql_error(mysql));
			rad_sql_need_reconnect(conn->type);
			return ret;
		}
	}
	debug(1,("FAILURE"));
	radlog(L_ERR, _("MYSQL Error (giving up): Cannot Query:%s"), query);
	rad_sql_need_reconnect(conn->type);
	return ret;
}

/* ************************************************************************* */
/* Interface routines */
int
rad_sql_reconnect(type, conn)
	int    type;
	struct sql_connection *conn;
{
	int   i;
	MYSQL *mysql = NULL;
	char *dbname;
	
	mysql_port = sql_cfg.port;

	conn->data = alloc_entry(sizeof(MYSQL));
	
	for (i = 0; !mysql && i < 10; i++) {	/* Try it 10 Times */
		if (!(mysql_connect((MYSQL*)conn->data,
				    sql_cfg.server,
				    sql_cfg.login,
				    sql_cfg.password))) {
			radlog(L_ERR,
			       _("MYSQL: cannot connect to %s as %s"),
			       sql_cfg.server,
			       sql_cfg.login);
		} else {
			debug(1,
				("connected to %s", sql_cfg.server));
			mysql = (MYSQL*)conn->data;
			conn->connected++;
		}
	}

	switch (type) {
	case SQL_AUTH:
		dbname = sql_cfg.auth_db;
		break;
	case SQL_ACCT:
		dbname = sql_cfg.acct_db;
		break;
	}
	
	if (mysql != NULL) {
		for (i = 0; i < 10; i++) {/* Try it 10 Times  */
			if (mysql_select_db(mysql, dbname)) {
				radlog(L_ERR, _("MYSQL cannot select db %s"), 
				       dbname);
				radlog(L_ERR, _("MYSQL error: %s"), 
				       mysql_error(mysql));
			} else {
				radlog(L_INFO,
				       _("MYSQL Connected to db %s"),
				       dbname);
				return 0;
			}
		}
	}

	free_entry(conn->data);
	conn->data = NULL;
	radlog(L_ERR, _("MYSQL: Giving up on connect"));
	rad_sql_need_reconnect(type);
	return -1;
}

void 
rad_sql_disconnect(conn)
	struct sql_connection *conn;
{
	mysql_close(conn->data);
	free_entry(conn->data);
}

int
rad_sql_query(conn, query, return_count)
	struct sql_connection *conn;
	char *query;
	int *return_count;
{
	if (!conn) 
		return -1;

	if (do_mysql_query(conn, query, MYSQL_ACCT)) {
		radlog(L_ERR, _("MYSQL Error: query %s"), query);
		return -1;
	}
	
	if (return_count != NULL) 
		*return_count = mysql_affected_rows((MYSQL*)conn->data);

	return 0;
}

char *
rad_sql_getpwd(conn, query)
	struct sql_connection *conn;
	char *query;
{
	MYSQL_RES      *result;
	MYSQL_ROW       row;
	char *return_passwd;
	
	if (!conn)
		return NULL;

	debug(1, ("query: %s", query));

	if (do_mysql_query(conn, query, MYSQL_AUTH))
		return NULL;

	if (!(result = mysql_store_result((MYSQL*)conn->data))) {
		radlog(L_ERR,
		       _("MYSQL Error: can't get result for authentication"));
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


#endif /* defined (USE_SQL) && defined(USE_SQL_MYSQL) */
