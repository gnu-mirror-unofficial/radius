/* This file is part of GNU RADIUS.
 * Copyright (C) 2000,2001, Sergey Poznyakoff
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

#define RADIUS_MODULE 9
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#if defined(USE_SQL)

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <radiusd.h>
#include <radsql.h>
#include <obstack1.h>
#include <ctype.h>

static void sql_check_config(SQL_cfg *);
static struct sql_connection *create_sql_connection(int type);
static struct sql_connection *attach_sql_connection(int type, qid_t qid);
static void unattach_sql_connection(int type, qid_t  qid);
static void free_sql_connection(int type, qid_t qid);
static void close_sql_connections(int type);

static char *getline();
static int get_boolean(char *str, int *retval);
static int get_unsigned(char *str, unsigned *retval);
static char * sql_digest(SQL_cfg *cfg);
static int sql_digest_comp(char *d1, char *d2);
static int sql_cfg_comp(SQL_cfg *a, SQL_cfg *b);
static int chop(char *str);
static void sql_flush();

SQL_cfg sql_cfg;

#define STMT_SERVER                 1
#define STMT_PORT                   2
#define STMT_LOGIN                  3
#define STMT_PASSWORD               4
#define STMT_KEEPOPEN               5
#define STMT_DOAUTH                 6
#define STMT_DOACCT                 7
#define STMT_AUTH_DB                8
#define STMT_ACCT_DB                9
#define STMT_AUTH_QUERY            10
#define STMT_ACCT_START_QUERY      11
#define STMT_ACCT_STOP_QUERY       12
#define STMT_ACCT_NASUP_QUERY      13
#define STMT_ACCT_NASDOWN_QUERY    14
#define STMT_ACCT_KEEPALIVE_QUERY  15
#define STMT_QUERY_BUFFER_SIZE     16
#define STMT_IDLE_TIMEOUT          17
#define STMT_MAX_AUTH_CONNECTIONS  18
#define STMT_MAX_ACCT_CONNECTIONS  19
#define STMT_GROUP_QUERY           20
#define STMT_ATTR_QUERY            21
#define STMT_INTERFACE             22

static FILE  *sqlfd;
static int line_no;
static char *cur_line, *cur_ptr;
static struct obstack stack;
static int obstack_ready;
static int stmt_type;

struct keyword sql_keyword[] = {
	"server",             STMT_SERVER,
	"port",               STMT_PORT,
	"login",              STMT_LOGIN,
	"password",           STMT_PASSWORD,
	"keepopen",           STMT_KEEPOPEN,
	"idle_timeout",       STMT_IDLE_TIMEOUT,
	"auth_max_connections", STMT_MAX_AUTH_CONNECTIONS,
	"acct_max_connections", STMT_MAX_ACCT_CONNECTIONS,
	"doauth",             STMT_DOAUTH,
	"doacct",             STMT_DOACCT,
	"auth_db",            STMT_AUTH_DB,
	"acct_db",            STMT_ACCT_DB,
	"auth_query",         STMT_AUTH_QUERY,
	"group_query",        STMT_GROUP_QUERY,
	"attr_query",         STMT_ATTR_QUERY, 
	"acct_start_query",   STMT_ACCT_START_QUERY,
	"acct_stop_query",    STMT_ACCT_STOP_QUERY,
	"acct_alive_query",   STMT_ACCT_KEEPALIVE_QUERY,
	"acct_keepalive_query", STMT_ACCT_KEEPALIVE_QUERY,
	"acct_nasup_query",   STMT_ACCT_NASUP_QUERY,
	"acct_nasdown_query", STMT_ACCT_NASDOWN_QUERY,
	"interface",          STMT_INTERFACE,
	NULL,
};

static char *service_name[SQL_NSERVICE] = {
	"AUTH",
	"ACCT"
};

static char *reconnect_file[SQL_NSERVICE] = {
	"auth.reconnect",
	"acct.reconnect"
};


/*
 * Chop off trailing whitespace. Return length of the resulting string
 */
int
chop(str)
	char *str;
{
	int len;

	for (len = strlen(str); len > 0 && isspace(str[len-1]); len--)
		;
	str[len] = 0;
	return len;
}

char *
getline()
{
	char buf[256];
	char *ptr;
	int len, eff_len;
	int total_length = 0;
	int cont;

	if (cur_line)
		obstack_free(&stack, cur_line);
	cont = 1;
	while (cont) {
		ptr = fgets(buf, sizeof(buf), sqlfd);
		if (!ptr)
			break;
		line_no++;
		
		/* Skip empty lines and comments */
		while (*ptr && isspace(*ptr))
			ptr++;
		if (!*ptr || *ptr == '#')
			continue;
		/* chop trailing spaces */
		/* note: len is guaranteed to be > 0 */
		len = strlen(ptr) - 1;
		while (len > 0 && isspace(ptr[len]))
			len--;
		
		/* compute effective length */
		eff_len = (cont = ptr[len] == '\\') ? len : len + 1;
		if (eff_len == 0)
			continue;
		total_length += eff_len;
		/* add to the stack */
		obstack_grow(&stack, ptr, eff_len);
	} 

	if (total_length == 0)
		return NULL;
	obstack_1grow(&stack, 0);
	cur_ptr = cur_line = obstack_finish(&stack);
	/* recognize keyword */
	while (*cur_ptr && !isspace(*cur_ptr))
		cur_ptr++;
	if (*cur_ptr) {
		*cur_ptr++ = 0;
		while (*cur_ptr && isspace(*cur_ptr))
			cur_ptr++;
	}
	stmt_type = xlat_keyword(sql_keyword, cur_line, -1);
	return cur_ptr;
}

int
get_boolean(str, retval)
	char *str;
	int *retval;
{
	if (strcmp(str, "yes") == 0)
		*retval = 1;
	else if (strcmp(str, "no") == 0)
		*retval = 0;
	else
		return 1;
	return 0;
}

int
get_unsigned(str, retval)
	char *str;
	unsigned *retval;
{
	unsigned val;
	
	val = strtol(str, &str, 0);
	if (*str != 0 && !isspace(*str))
		return 1;

	*retval = val;
	return 0;
}

char *
sql_digest(cfg)
	SQL_cfg *cfg;
{
	int length;
	char *digest, *p;
	
#define STRLEN(a) (a ? strlen(a) : 0)
#define STPCPY(d,s) if (s) { strcpy(d,s); d += strlen(s); }
	
	length =  6 * sizeof(int)
		+ 2 * sizeof(unsigned)
		+ STRLEN(cfg->server)
		+ STRLEN(cfg->login)
		+ STRLEN(cfg->password)
		+ STRLEN(cfg->auth_db)
		+ STRLEN(cfg->acct_db)
		+ 1;

	digest = emalloc(length);
	p = digest;
	
	*(int*)p = length;
	p += sizeof(int);

	*(int*)p = cfg->interface;
	p += sizeof(int);
	
	*(int*)p = cfg->keepopen;
	p += sizeof(int);
	
	*(int*)p = cfg->doauth;
	p += sizeof(int);
	
	*(int*)p = cfg->doacct;
	p += sizeof(int);
	
	*(int*)p = cfg->port;
	p += sizeof(int);

	*(unsigned*)p = cfg->max_connections[SQL_AUTH];
	p += sizeof(unsigned);

	*(unsigned*)p = cfg->max_connections[SQL_ACCT];
	p += sizeof(unsigned);
	
	STPCPY(p, cfg->server);
	STPCPY(p, cfg->login);
	STPCPY(p, cfg->password);
	STPCPY(p, cfg->auth_db);
	STPCPY(p, cfg->acct_db);

	return digest;
}

int
sql_digest_comp(d1, d2)
	char *d1, *d2;
{
	int len;

	len = *(int*)d1;
	if (len != *(int*)d2)
		return 1;
	return memcmp(d1, d2, len);
}

int
sql_cfg_comp(a, b)
	SQL_cfg *a, *b;
{
	char *dig1, *dig2;
	int rc;
	
	dig1 = sql_digest(a);
	dig2 = sql_digest(b);
	rc = sql_digest_comp(dig1, dig2);
	efree(dig1);
	efree(dig2);
	return rc;
}

int 
rad_sql_init()
{
	char *sqlfile;
	UINT4 ipaddr;
	char *ptr;
	size_t bufsize = 0;
	time_t timeout;
	SQL_cfg new_cfg;

#define FREE(a) if (a) efree(a); a = NULL

	bzero(&new_cfg, sizeof(new_cfg));
	new_cfg.keepopen = 0;
	new_cfg.idle_timeout = 4*3600; /* four hours */
	new_cfg.max_connections[SQL_AUTH] = 16;
	new_cfg.max_connections[SQL_ACCT] = 16;
	new_cfg.doacct = 0;
	new_cfg.doauth = 0;

	sqlfile = mkfilename(radius_dir, "sqlserver");
	/* Open source file */
	if ((sqlfd = fopen(sqlfile, "r")) == (FILE *) NULL) {
		radlog(L_ERR, _("could not read sqlserver file %s"), sqlfile);
		efree(sqlfile);
		return -1;
	}
	line_no = 0;
	cur_line = NULL;
	if (!obstack_ready) {
		obstack_init(&stack);
		obstack_ready = 1;
	} 
	while (getline()) {
		if (stmt_type == -1) {
			radlog(L_ERR,
			       _("%s:%d: unrecognized keyword"),
			       sqlfile, line_no);
			continue;
		}
		/* Each keyword should have an argument */
		if (cur_ptr == NULL) {
			radlog(L_ERR,
			       _("%s:%d: required argument missing"),
			       sqlfile, line_no);
			continue;
		}
		
		switch (stmt_type) {
		case STMT_SERVER:
			ipaddr = get_ipaddr(cur_ptr);
			if (ipaddr == (UINT4)0) {
				radlog(L_ERR,
				       _("%s:%d: unknown host: %s"),
				       sqlfile, line_no,
				       cur_ptr);
				new_cfg.doacct = 0;
				new_cfg.doauth = 0;
			} else {
				new_cfg.server = estrdup(cur_ptr);
			}
			break;
			
		case STMT_PORT:
			new_cfg.port = strtol(cur_ptr, &ptr, 0);
			if (*ptr != 0 && !isspace(*ptr)) {
				radlog(L_ERR, _("%s:%d: number parse error"),
				       sqlfile, line_no);
				new_cfg.doacct = 0;
				new_cfg.doauth = 0;
			}
			break;
			
		case STMT_LOGIN:
			new_cfg.login = estrdup(cur_ptr);
			break;
			
		case STMT_PASSWORD:
			new_cfg.password = estrdup(cur_ptr);
			break;
			
		case STMT_KEEPOPEN:
			if (get_boolean(cur_ptr, &new_cfg.keepopen))
				radlog(L_ERR,
				       _("%s:%d: expected boolean value"),
				       sqlfile, line_no);
			break;

		case STMT_IDLE_TIMEOUT:
			timeout = strtol(cur_ptr, &ptr, 0);
			if ((*ptr != 0 && !isspace(*ptr)) || timeout <= 0) {
				radlog(L_ERR, _("%s:%d: number parse error"),
				       sqlfile, line_no);
			} else 
				new_cfg.idle_timeout = timeout;
			break;
			
		case STMT_MAX_AUTH_CONNECTIONS:
			if (get_unsigned(cur_ptr,
					 &new_cfg.max_connections[SQL_AUTH])) 
				radlog(L_ERR, _("%s:%d: number parse error"),
				       sqlfile, line_no);
			break;
			
		case STMT_MAX_ACCT_CONNECTIONS:
			if (get_unsigned(cur_ptr,
					 &new_cfg.max_connections[SQL_ACCT])) 
				radlog(L_ERR, _("%s:%d: number parse error"),
				       sqlfile, line_no);
			break;
			
		case STMT_DOAUTH:	
			if (get_boolean(cur_ptr, &new_cfg.doauth))
				radlog(L_ERR,
				       _("%s:%d: expected boolean value"),
				       sqlfile, line_no);
			break;
			
		case STMT_DOACCT:
			if (get_boolean(cur_ptr, &new_cfg.doacct))
				radlog(L_ERR,
				       _("%s:%d: expected boolean value"),
				       sqlfile, line_no);
			break;
			
		case STMT_AUTH_DB:
			new_cfg.auth_db = estrdup(cur_ptr);
			break;

		case STMT_ACCT_DB:
			new_cfg.acct_db = estrdup(cur_ptr);
			break;
			
		case STMT_AUTH_QUERY:
			new_cfg.auth_query = estrdup(cur_ptr);
			break;

		case STMT_GROUP_QUERY:
			new_cfg.group_query = estrdup(cur_ptr);
			break;
			
		case STMT_ACCT_START_QUERY:
			new_cfg.acct_start_query = estrdup(cur_ptr);
			break;
			
		case STMT_ACCT_STOP_QUERY:
			new_cfg.acct_stop_query = estrdup(cur_ptr);
			break;
			
		case STMT_ACCT_KEEPALIVE_QUERY:
			new_cfg.acct_keepalive_query = estrdup(cur_ptr);
			break;
			
		case STMT_ACCT_NASUP_QUERY:
			new_cfg.acct_nasup_query = estrdup(cur_ptr);
			break;

		case STMT_ACCT_NASDOWN_QUERY:
			new_cfg.acct_nasdown_query = estrdup(cur_ptr);
			break;
			
		case STMT_ATTR_QUERY:
			new_cfg.attr_query = estrdup(cur_ptr);
			break;

		case STMT_QUERY_BUFFER_SIZE:
			radlog(L_WARN, "%s:%d: query_buffer_size is obsolete",
				       sqlfile, line_no);
			break;
			
		case STMT_INTERFACE:
			new_cfg.interface = disp_sql_interface_index(cur_ptr);
			if (!new_cfg.interface) {
				radlog(L_WARN, "%s:%d: Unsupported SQL interface.",
				       sqlfile, line_no);
			}
			break;
		}
		
	}

	if (cur_line)
		obstack_free(&stack, cur_line);
//	obstack_free(&stack,NULL);
	fclose(sqlfd);
	efree(sqlfile);

	sql_check_config(&new_cfg);

	if (sql_cfg_comp(&new_cfg, &sql_cfg)) 
		sql_flush();

	/* Free old configuration structure */
	FREE(sql_cfg.server);
	FREE(sql_cfg.login);
	FREE(sql_cfg.password);
	FREE(sql_cfg.acct_db) ;
	FREE(sql_cfg.auth_db);
	FREE(sql_cfg.group_query);
	FREE(sql_cfg.auth_query);
	FREE(sql_cfg.acct_start_query);
	FREE(sql_cfg.acct_stop_query);
	FREE(sql_cfg.acct_nasup_query);
	FREE(sql_cfg.acct_nasdown_query);
	FREE(sql_cfg.acct_keepalive_query);
	FREE(sql_cfg.attr_query);

	/* copy new config */
	sql_cfg = new_cfg;
		
	return 0;
}

void
rad_sql_shutdown()
{
	close_sql_connections(SQL_AUTH);
	close_sql_connections(SQL_ACCT);
}

void
sql_check_config(cfg)
	SQL_cfg *cfg;
{
#define FREE_IF_EMPTY(s) if (s && strcmp(s, "none") == 0) {\
				efree(s);\
				s = NULL;\
			 }
	/*
	 * Check if we should do SQL authentication
	 */
	if (cfg->doauth) {
		FREE_IF_EMPTY(cfg->auth_query);
		if (!cfg->auth_query) {
			radlog(L_ERR,
			    _("disabling SQL auth: no auth_query specified"));
			cfg->doauth = 0;
		}
		if (!cfg->group_query) {
			radlog(L_WARN,
			       _("SQL auth: no group_query specified"));
		}
		FREE_IF_EMPTY(cfg->group_query);
	}
	/*
	 * Check if we should do SQL accounting
	 */
	if (cfg->doacct) {
		if (!cfg->acct_start_query) {
			radlog(L_WARN,
			       _("SQL acct: no acct_start_query specified"));
		}
		FREE_IF_EMPTY(cfg->acct_start_query);

		if (!cfg->acct_stop_query) {
			radlog(L_ERR,
		     _("disabling SQL acct: no acct_stop_query specified"));
			cfg->doacct = 0;
		}
		FREE_IF_EMPTY(cfg->acct_stop_query);

		if (!cfg->acct_nasdown_query) {
			radlog(L_WARN,
		     _("SQL acct: no acct_nasdown_query specified"));
		}
		FREE_IF_EMPTY(cfg->acct_nasdown_query);

		if (!cfg->acct_nasup_query) {
			radlog(L_WARN,
		     _("SQL acct: no acct_nasup_query specified"));
		}
		FREE_IF_EMPTY(cfg->acct_nasup_query);
	}
	
	debug(1, ("SQL init using: %s:%d,%s,%s,%s,%d,%ld,%d,%d",
	       cfg->server,
	       cfg->port,
	       cfg->login,
	       cfg->acct_db,
	       cfg->auth_db,
	       cfg->keepopen,
	       cfg->idle_timeout,
	       cfg->doacct,
	       cfg->doauth));
}

/* ************************************************************************* */
/* Internal routines
 *
 * All SQL connections are kept in a singly-linked list. The connection
 * immediately at the head of the list is the one that is going to be used
 * on the next call. After use, the connection is moved to the end
 * of the list. The connections are thus sorted in LRU manner.
 * 
 */

/* The connection list
 */
static struct sql_connection *conn_first; /* First connection: the one
					   * to be used
					   */
static struct sql_connection *conn_last;  /* Last connection: the most
					   * recently used one.
					   */
static int conn_count[SQL_NSERVICE];      /* number of connections in list */

static void
print_queue()
{
	struct sql_connection *conn, *prev;
	int i = 0;
	
	if (debug_on(10)) {
		debug(10, ("Connection queue: %p - %p, %d;%d:",
			     conn_first,
			     conn_last,
			     conn_count[SQL_AUTH], conn_count[SQL_ACCT]));
		prev = NULL;
		for (conn = conn_first; conn; conn = conn->next) {
			debug(10, ("%d: %p (%d) %d",
				     i++, conn, conn->type, conn->qid));
			prev = conn;
		}
		insist(conn_last == prev);
	}
}

void
sql_flush()
{
	if (conn_first != NULL) {
		radlog(L_NOTICE,
		 _("SQL configuration changed: closing existing connections"));

		rad_flush_queues();
		
		close_sql_connections(SQL_AUTH);
		close_sql_connections(SQL_ACCT);
	}
}

/* Create the new SQL connection and attach it to the head of the
 * list.
 */
struct sql_connection *
create_sql_connection(type)
	int   type;
{
	struct sql_connection *conn;

	debug(1, ("allocating new %d sql connection", type));
	print_queue();

	conn = alloc_entry(sizeof(struct sql_connection));
	conn->qid = 0;
	conn->type = type;

	/* attach to the head of the list */
	conn->next = conn_first;
	conn_first = conn;
	if (!conn_last)
		conn_last = conn;

	conn_count[type]++;
	disp_sql_reconnect(sql_cfg.interface, type, conn);	
	return conn;
}

/* Close the existing SQL connection, unlink it from the list and deallocate
 * the memory associated with it
 * Arguments:
 *        conn     -     the connection to be closed
 *        prev     -     the previous connection in the list
 */
void
close_sql_connection(conn, prev)
	struct sql_connection *conn, *prev;
{
	debug(1, ("destructing sql connection: %d left in queue",
		 conn_count[SQL_AUTH] + conn_count[SQL_ACCT] - 1));
	
	if (conn->connected)
		disp_sql_disconnect(sql_cfg.interface, conn);
	if (prev)
		prev->next = conn->next;
	if (conn_first == conn)
		conn_first = conn->next;
	if (conn_last == conn)
		conn_last = prev;
	conn_count[conn->type]--;
	free_entry(conn);
}

/* Attach the SQL connection of the given type and queue id to the connection
 * list:
 *       1. Scan the list for the first unused connection of the given type
 *       2. If not found, allocate one.
 *       3. Mark the connection with new queue id, update its last usage
 *          timestamp and return.
 *       Additionally, while scanning, close all connections which have been
 *       idle for more than sql_cfg.idle_timeout seconds.
 *
 * Modified by kaz:
 *       Remove the code to scan for idle connections.  
 *
 *       Why?  This function is only called when the RADIUS server is
 *       about to log something to the SQL server. It is called in two
 *       places: in the master_process when it calls request_setup and 
 *       when the child process calls rad_accounting/rad_authenticate. 
 *
 *       Whats the problem?  If the RADIUS server is configured to 
 *       "keepopen" the SQL connections, then there is a potential 
 *       that the RADIUS server may be idle for a time greater than 
 *       the time expected by the SQL server's idle timeout, which 
 *       could result in an error.  On MySQL, it will complain about 
 *       an "Aborted connection ## to db".  For example, my RADIUS 
 *       server was using "keepopen", but it was not very busy.  My
 *       database "MySQL" was configured with a default "wait_timeout"
 *       of 8 hours.  Everytime, the 8 hours were exceeded, MySQL would
 *       mark the connection dead, yet, the RADIUS server still thought
 *       the connection was open and it resulted in error messages in 
 *       my MySQL logs.
 *
 *       Whats the solution?  Move the idle checking to the main loop
 *       of radiusd.c.  rad_select should be modified to wait only for 
 *       a fixed interval, perhaps 60 seconds, instead of blocking 
 *       indefinitely.  A new function should also be created in sql.c
 *       called rad_sql_idle_check() which will close connections that
 *       are now idle.
 */
struct sql_connection *
attach_sql_connection(type, qid)
	int type;
	qid_t qid;
{
	struct sql_connection *conn = NULL, *prev, *next;
	time_t now = time(NULL);

	debug(1, ("attaching %d,%d", type, qid));

	prev = NULL;
	if (sql_cfg.keepopen) {
		print_queue();

		conn = conn_first;
		while (conn) {
			if (conn->type == type) { 
				if (conn->qid == qid)
					return conn;
				if (conn->qid == 0)
					break;
			}
			next = conn->next;
			prev = conn;
			conn = next;
		}
	}
	
	if (!conn) {

		insist(conn_last == prev);
		
		if (conn_count[type] >= sql_cfg.max_connections[type]) {
			radlog(L_CRIT,
	 _("can't create new %s SQL connection: too many connections open"),
			       service_name[type]);
			return NULL;
		}
		
		conn = create_sql_connection(type);
	}
	conn->qid = qid;
	conn->last_used = now;
	return conn;
}

/* Unattach the SQL connection. Move it to the end of the list.
 */
void
unattach_sql_connection(type, qid)
	int    type;
	qid_t  qid;
{
	struct sql_connection *conn, *prev;

	if (sql_cfg.keepopen == 0) {
		free_sql_connection(type, qid);
		return;
	}
	debug(1, ("unattaching connection %d,%d", type,qid));

	prev = NULL;
	conn = conn_first;
	while (conn) {
		if (conn->type == type && conn->qid == qid) {
			debug(5, ("unattaching connection: found"));
			conn->qid = 0;

			if (!master_process())
				return;
			
			if (conn_last == conn)
				return;

			/* Unattach the connection from the list
			 */
			if (conn_first == conn)
				conn_first = conn->next;
			else if (prev)
				prev->next = conn->next;
			conn->next = NULL;
			
			/* Append it to the end of list
			 */
			conn_last->next = conn;
			conn_last = conn;

			return;
		}
		prev = conn;
		conn = conn->next;
	}
	print_queue();
}

/* Unlink from the list the SQL connection identified by type and queue id,
 * close it and free the memory associated with it.
 */
void
free_sql_connection(type, qid)
	int    type;
	qid_t  qid;
{
	struct sql_connection *conn, *prev;

	prev = NULL;
	conn = conn_first;
	while (conn) {
		if (conn->type == type && conn->qid == qid) {
			close_sql_connection(conn, prev);
			return;
		}

		prev = conn;
		conn = conn->next;
	}
}

/* Close and deallocate all SQL connections
 */
void
close_sql_connections(type)
	int    type;
{
	struct sql_connection *conn, *prev, *next;

	debug(1, ("closing all %s connections", service_name[type]));
	
	prev = NULL;
	conn = conn_first;
	while (conn) {
		if (conn->type == type) {
			next = conn->next;
			close_sql_connection(conn, prev);
			conn = next;
		} else {
			prev = conn;
			conn = conn->next;
		}
	}
}

/* ************************************************************************* */

int
rad_sql_setup(type, qid)
	int type;
	qid_t qid;
{
	insist(type >= 0 && type < SQL_NSERVICE);

	if (!sql_cfg.keepopen)
		return 0;
	
	if (sql_cfg.active[type]) {
		attach_sql_connection(type, qid); 
	}
	return 0;
}

void
rad_sql_idle_check(void)
{
  	struct sql_connection *conn = NULL, *prev, *next;
  	time_t now = time(NULL);

  	prev = NULL;
	
  	if (sql_cfg.keepopen) {
    		conn = conn_first;
    		while (conn) {
			next = conn->next;

			if (master_process() &&
			    conn->qid == 0 &&
			    (now - conn->last_used) >= sql_cfg.idle_timeout) {
				/* Close the idle connection */
				debug(1,
				      ("connection reached idle timeout: %p,%d",
				       conn, conn->type));
				close_sql_connection(conn, prev);
			} else
				prev = conn;

			conn = next;
		}
	}
}

void
rad_sql_cleanup(type, qid)
	int type;
	qid_t qid;
{
	insist(type >= 0 && type < SQL_NSERVICE);

	if (!sql_cfg.keepopen)
		return;

	if (sql_cfg.active[type])
		unattach_sql_connection(type, qid);
}

void
rad_sql_need_reconnect(type)
	int type;
{
	int fd;
	char *path;

	insist(type >= 0 && type < SQL_NSERVICE);
	if (master_process())
		return;
	if (sql_cfg.keepopen && sql_cfg.active[type]) {
		path = mkfilename(radius_dir, reconnect_file[type]);
		fd = open(path, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd == -1) 
			radlog(L_ERR|L_PERROR, 
				_("can't create file: %s"), path);
		else 
			close(fd);
		efree(path);
	}
}


void
rad_sql_check_connect(type)
	int type;
{
	char *path;
	int  pass = 0;
	
	insist(type >= 0 && type < SQL_NSERVICE);

	path = mkfilename(radius_dir, reconnect_file[type]);
	if (access(path, F_OK) == 0) {
		unlink(path);
		pass++;
	}
	efree(path);
	if (pass)
		close_sql_connections(type);
	
}

/*
 * Perform normal accounting
 */ 
void
rad_sql_acct(radreq)
	RADIUS_REQ *radreq;
{
	int rc, count;
	int status;
	VALUE_PAIR *pair;
	char *query;
	struct sql_connection *conn;
	
	if (!sql_cfg.doacct)
		return;

	if ((pair = avl_find(radreq->request, DA_ACCT_STATUS_TYPE)) == NULL) {
		/* should never happen!! */
		radlog(L_ERR, _("no Acct-Status-Type record in rad_sql_acct()"));
		return ;
	}
	status = pair->lvalue;

	conn = attach_sql_connection(SQL_ACCT, (qid_t)radreq);

	switch (status) {
	case DV_ACCT_STATUS_TYPE_START:
		if (!sql_cfg.acct_start_query)
			break;
		query = radius_xlate(&stack,
				     sql_cfg.acct_start_query,
				     radreq, NULL);
		rc = disp_sql_query(sql_cfg.interface, conn, query, NULL);
		sqllog(rc, query);
		break;
		
	case DV_ACCT_STATUS_TYPE_STOP:
		if (!sql_cfg.acct_stop_query)
			break;
		query = radius_xlate(&stack,
				     sql_cfg.acct_stop_query,
				     radreq, NULL);
		rc = disp_sql_query(sql_cfg.interface, conn, query, &count);
		sqllog(rc, query);
		if (rc == 0 && count != 1) {
			char *name;
			char *session_id;

			pair = avl_find(radreq->request, DA_USER_NAME);
			name = pair ? pair->strvalue : _("unknown");
			pair = avl_find(radreq->request, DA_ACCT_SESSION_ID);
			session_id = pair ? pair->strvalue : _("unknown");
			radlog(L_WARN, 
			       _("SQL %s (%s) %d rows changed"),
			       name, session_id, count);
		}
		break;

	case DV_ACCT_STATUS_TYPE_ACCOUNTING_ON:
		if (!sql_cfg.acct_nasup_query)
			break;
		query = radius_xlate(&stack,
				     sql_cfg.acct_nasup_query,
				     radreq, NULL);
		rc = disp_sql_query(sql_cfg.interface, conn, query, &count);
		sqllog(rc, query);
		if (rc == 0) {
			radlog(L_INFO,
			       _("SQL: %d records updated writing acct-on info for NAS %s"),
			       count,
			       nas_request_to_name(radreq));
		}
		break;

	case DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF:
		if (!sql_cfg.acct_nasdown_query)
			break;
		query = radius_xlate(&stack,
				     sql_cfg.acct_nasdown_query,
				     radreq, NULL);
		rc = disp_sql_query(sql_cfg.interface, conn, query, &count);
		sqllog(rc, query);
		if (rc == 0) {
			radlog(L_INFO,
			       _("SQL: %d records updated writing acct-off info for NAS %s"),
			       count,
			       nas_request_to_name(radreq));
		}
		break;

	case DV_ACCT_STATUS_TYPE_ALIVE:
		if (!sql_cfg.acct_keepalive_query)
			break;
		query = radius_xlate(&stack,
				     sql_cfg.acct_keepalive_query,
				     radreq, NULL);
		rc = disp_sql_query(sql_cfg.interface, conn, query, &count);
		sqllog(rc, query);
		if (rc != 0) {
			radlog(L_INFO,
			       _("SQL: %d records updated writing keepalive info for NAS %s"),
			       count,
			       nas_request_to_name(radreq));
		}
		break;
		
	}

	if (!sql_cfg.keepopen)
		unattach_sql_connection(SQL_ACCT, (qid_t)radreq);

	if (query)
		obstack_free(&stack, query);
}


int
rad_sql_pass(req, authdata, passwd)
	RADIUS_REQ *req;
	char *authdata;
	char *passwd;
{
	int   rc;
	char *mysql_passwd;
	struct sql_connection *conn;
	char *query;

	if (sql_cfg.doauth == 0) {
		radlog(L_ERR,
		       _("SQL Auth specified in users file, but not in sqlserver file"));
		return AUTH_FAIL;
	}
	
	if (authdata) {
		avl_add_pair(&req->request,
			avp_create(DA_AUTH_DATA,
				    strlen(authdata),
				    authdata, 0));
	}
	query = radius_xlate(&stack, sql_cfg.auth_query, req, NULL);
	avl_delete(&req->request, DA_AUTH_DATA);
	
	conn = attach_sql_connection(SQL_AUTH, (qid_t)req);
	mysql_passwd = disp_sql_getpwd(sql_cfg.interface, conn, query);
	
	if (!mysql_passwd) {
		rc = AUTH_NOUSER;
	} else {
		chop(mysql_passwd);
		if (strcmp(mysql_passwd, md5crypt(passwd, mysql_passwd)) == 0)
			rc = AUTH_OK;
		else
			rc = AUTH_FAIL;
		efree(mysql_passwd);
	}
	
	if (!sql_cfg.keepopen)
		unattach_sql_connection(SQL_AUTH, (qid_t)req);
	
	if (!query)
		obstack_free(&stack, query);
	
	return rc;
}

int
rad_sql_checkgroup(req, groupname)
	RADIUS_REQ *req;
	char *groupname;
{
	int   rc = -1;
	struct sql_connection *conn;
	void *data;
	char *p;
	char *query;
	
	if (sql_cfg.doauth == 0 || sql_cfg.group_query == NULL) 
		return -1;

	query = radius_xlate(&stack, sql_cfg.group_query, req, NULL);

	conn = attach_sql_connection(SQL_AUTH, (qid_t)req);
	data = disp_sql_exec(sql_cfg.interface, conn, query);
	while (rc != 0 && disp_sql_next_tuple(sql_cfg.interface, conn, data) == 0) {
		if ((p = disp_sql_column(sql_cfg.interface, data, 0)) == NULL)
			break;
		chop(p);
		if (strcmp(p, groupname) == 0)
			rc = 0;
	}
	disp_sql_free(sql_cfg.interface, conn, data);
	
	if (!sql_cfg.keepopen)
		unattach_sql_connection(SQL_AUTH, (qid_t)req);
	
	if (query)
		obstack_free(&stack, query);
	return rc;
}

int
rad_sql_attr_query(req, reply_pairs)
        RADIUS_REQ *req;
        VALUE_PAIR **reply_pairs;
{
        VALUE_PAIR *request_pairs = req->request;
	struct sql_connection	*conn;
	void			*data;
	char			*attribute;
	char			*value;
	char			*cols_array[2];
	VALUE_PAIR		*pair;
	int			i;
	qid_t                   qid;
	char *query;

	if (sql_cfg.doauth == 0 || !sql_cfg.attr_query)
		return 0;
	
	if ((pair = avl_find(request_pairs, DA_QUEUE_ID)) == NULL) {
		/* this should never happen, but just in case... */
		radlog(L_ERR, "No queue ID in request");
		return -1;
	}
	qid = (qid_t)pair->lvalue;
	conn = attach_sql_connection(SQL_AUTH, qid);
	
	query = radius_xlate(&stack, sql_cfg.attr_query, req, NULL);
	
        data = disp_sql_exec(sql_cfg.interface, conn, query);
	if (!data)
		return 0;
	
        for (i = 0; disp_sql_next_tuple(sql_cfg.interface, conn, data) == 0; i++) {
                if (!(attribute = disp_sql_column(sql_cfg.interface, data, 0))
		    || !(value = disp_sql_column(sql_cfg.interface, data, 1))) {
                        break;
                }
                chop(attribute);
		chop(value);

		pair = install_pair(attribute, PW_OPERATOR_EQUAL, value);
 
                if (pair)
                        avl_add_list(reply_pairs, pair);
        }
 
        disp_sql_free(sql_cfg.interface, conn, data);
 
        if (!sql_cfg.keepopen) 
                unattach_sql_connection(SQL_AUTH, qid);

	if (query)
		obstack_free(&stack, query);
	return i == 0;
}



#endif
