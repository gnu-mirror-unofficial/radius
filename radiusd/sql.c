/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <radiusd.h>

#ifdef USE_SERVER_GUILE
# include <libguile.h>
# include <radscm.h>
#endif

#if defined(USE_SQL)

static void sql_check_config(const char *, SQL_cfg *);
static struct sql_connection *attach_sql_connection(int type);
static void detach_sql_connection(int type);
static void sql_conn_destroy(struct sql_connection **conn);
static void sql_cache_destroy(struct sql_connection *conn);

static char *get_conf_line();
static int get_boolean(char *str, int *retval);
static char * sql_digest(SQL_cfg *cfg);
static int sql_digest_comp(char *d1, char *d2);
static int sql_cfg_comp(SQL_cfg *a, SQL_cfg *b);
static int chop(char *str);
static void sql_flush();

SQL_cfg sql_cfg;
static struct sql_connection *sql_conn[SQL_NSERVICE];

#define STMT_SERVER                 1
#define STMT_PORT                   2
#define STMT_LOGIN                  3
#define STMT_PASSWORD               4
#define STMT_KEEPOPEN               5
#define STMT_DOAUTH                 6
#define STMT_DOACCT                 7
#define STMT_AUTH_DB                8
#define STMT_ACCT_DB                9
#define STMT_ACCT_KEEPALIVE_QUERY  10
#define STMT_QUERY_BUFFER_SIZE     11
#define STMT_IDLE_TIMEOUT          12
#define STMT_MAX_AUTH_CONNECTIONS  13
#define STMT_MAX_ACCT_CONNECTIONS  14
#define STMT_INTERFACE             15
#define STMT_QUERY_BASE           100

#define STMT_QUERY(c) (STMT_QUERY_BASE+c)
#define STMT_QUERY_CODE(c) ((c)-STMT_QUERY_BASE)
#define STMT_QUERY_P(t) ((t)>=STMT_QUERY_BASE \
                         && STMT_QUERY_CODE(t)<num_radius_sql_query)


/* *********************** Configuration File Parser *********************** */

static FILE  *sqlfd;
static int line_no;
static char *cur_line, *cur_ptr;
static struct obstack parse_stack;
static int stmt_type;

static grad_keyword_t sql_keyword[] = {
        { "server",             STMT_SERVER },
        { "port",               STMT_PORT },
        { "login",              STMT_LOGIN },
        { "password",           STMT_PASSWORD },
        { "keepopen",           STMT_KEEPOPEN },
        { "idle_timeout",       STMT_IDLE_TIMEOUT },
        { "auth_max_connections", STMT_MAX_AUTH_CONNECTIONS },
        { "acct_max_connections", STMT_MAX_ACCT_CONNECTIONS },
        { "doauth",             STMT_DOAUTH },
        { "doacct",             STMT_DOACCT },
        { "auth_db",            STMT_AUTH_DB },
        { "acct_db",            STMT_ACCT_DB },
        { "interface",          STMT_INTERFACE },
        { "auth_query",         STMT_QUERY(auth_query) },
        { "group_query",        STMT_QUERY(group_query) },
        { "attr_query",         STMT_QUERY(reply_attr_query) },
        { "reply_attr_query",   STMT_QUERY(reply_attr_query) },
        { "check_attr_query",   STMT_QUERY(check_attr_query) },
        { "acct_start_query",   STMT_QUERY(acct_start_query) },
        { "acct_stop_query",    STMT_QUERY(acct_stop_query) },
        { "acct_alive_query",   STMT_QUERY(acct_keepalive_query) },
        { "acct_keepalive_query", STMT_QUERY(acct_keepalive_query) },
        { "acct_nasup_query",   STMT_QUERY(acct_nasup_query) },
        { "acct_nasdown_query", STMT_QUERY(acct_nasdown_query) },
	{ "mlc_user_query",     STMT_QUERY(mlc_user_query) },
	{ "mlc_realm_query",    STMT_QUERY(mlc_realm_query) },
	{ "mlc_stop_query",     STMT_QUERY(mlc_stop_query) },
	{ "auth_success_query", STMT_QUERY(auth_success_query) },
	{ "auth_failure_query", STMT_QUERY(auth_failure_query) },
        { NULL }
};

static char *
sql_keyword_name(int kw)
{
	grad_keyword_t *p;

	for (p = sql_keyword; p->name; p++)
		if (p->tok == kw)
			return p->name;
	return NULL;
}

#define sql_query_name(c) sql_keyword_name(STMT_QUERY(c)) 

/*
 * Chop off trailing whitespace. Return length of the resulting string
 */
int
chop(char *str)
{
        int len;

        for (len = strlen(str); len > 0 && isspace(str[len-1]); len--)
                ;
        str[len] = 0;
        return len;
}

char *
get_conf_line()
{
        char buf[256];
        char *ptr;
        int len, eff_len;
        int total_length = 0;
        int cont;

        if (cur_line)
                obstack_free(&parse_stack, cur_line);
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
                obstack_grow(&parse_stack, ptr, eff_len);
        } 

        if (total_length == 0)
                return NULL;
        obstack_1grow(&parse_stack, 0);
        cur_ptr = cur_line = obstack_finish(&parse_stack);
        /* recognize keyword */
        while (*cur_ptr && !isspace(*cur_ptr))
                cur_ptr++;
        if (*cur_ptr) {
                *cur_ptr++ = 0;
                while (*cur_ptr && isspace(*cur_ptr))
                        cur_ptr++;
        }
        stmt_type = grad_xlat_keyword(sql_keyword, cur_line, -1);
        return cur_ptr;
}

int
get_boolean(char *str, int *retval)
{
        if (strcmp(str, "yes") == 0)
                *retval = 1;
        else if (strcmp(str, "no") == 0)
                *retval = 0;
        else
                return 1;
        return 0;
}

char *
sql_digest(SQL_cfg *cfg)
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

        digest = grad_emalloc(length);
        p = digest;
        
        *(int*)p = length;
        p += sizeof(int);

        *(int*)p = cfg->interface;
        p += sizeof(int);
        
        *(int*)p = cfg->keepopen;
        p += sizeof(int);
        
        *(int*)p = cfg->active[SQL_AUTH];
        p += sizeof(int);
        
        *(int*)p = cfg->active[SQL_ACCT];
        p += sizeof(int);
        
        *(int*)p = cfg->port;
        p += sizeof(int);

        STPCPY(p, cfg->server);
        STPCPY(p, cfg->login);
        STPCPY(p, cfg->password);
        STPCPY(p, cfg->auth_db);
        STPCPY(p, cfg->acct_db);

        return digest;
}

int
sql_digest_comp(char *d1, char *d2)
{
        int len;

        len = *(int*)d1;
        if (len != *(int*)d2)
                return 1;
        return memcmp(d1, d2, len);
}

static int
sql_cfg_empty_p(SQL_cfg *cfg)
{
	char *p;

	for (p = (char*)cfg; p < (char*)(cfg + 1); p++)
		if (*p)
			return 0;
	return 1;
}

int
sql_cfg_comp(SQL_cfg *a, SQL_cfg *b)
{
        char *dig1, *dig2;
        int rc;
        
        dig1 = sql_digest(a);
        dig2 = sql_digest(b);
        rc = sql_digest_comp(dig1, dig2);
        grad_free(dig1);
        grad_free(dig2);
        return rc;
}

int 
radiusd_sql_config()
{
        char *sqlfile;
        char *ptr;
        time_t timeout;
        SQL_cfg new_cfg;
	int i;
	
#define FREE(a) if (a) grad_free(a); a = NULL

        memset(&new_cfg, 0, sizeof(new_cfg));
        new_cfg.keepopen = 0;
        new_cfg.idle_timeout = 4*3600; /* four hours */
        new_cfg.active[SQL_ACCT] = 0;
        new_cfg.active[SQL_AUTH] = 0;

        sqlfile = grad_mkfilename(grad_config_dir, "sqlserver");
        /* Open source file */
        if ((sqlfd = fopen(sqlfile, "r")) == (FILE *) NULL) {
                grad_log(GRAD_LOG_ERR, _("could not read sqlserver file %s"), sqlfile);
                grad_free(sqlfile);
                return -1;
        }
        line_no = 0;
        cur_line = NULL;
        obstack_init(&parse_stack);
        while (get_conf_line()) {
                if (stmt_type == -1) {
                        grad_log(GRAD_LOG_ERR,
                                 "%s:%d: %s",
                                 sqlfile, line_no,
			         _("unrecognized keyword"));
                        continue;
                }
                /* Each keyword should have an argument */
                if (cur_ptr == NULL) {
                        grad_log(GRAD_LOG_ERR,
                                 "%s:%d: %s",
                                 sqlfile, line_no,
			         _("required argument missing"));
                        continue;
                }
                
                switch (stmt_type) {
                case STMT_SERVER:
                       	if (cur_ptr[0] != '/'
			    && !grad_ip_gethostaddr(cur_ptr)) {
                                grad_log(GRAD_LOG_ERR,
                                         _("%s:%d: unknown host: %s"),
                                         sqlfile, line_no,
                                         cur_ptr);
                                new_cfg.active[SQL_ACCT] = 0;
                                new_cfg.active[SQL_AUTH] = 0;
                        } else {
                                new_cfg.server = grad_estrdup(cur_ptr);
                        }
                        break;
                        
                case STMT_PORT:
                        new_cfg.port = strtol(cur_ptr, &ptr, 0);
                        if (*ptr != 0 && !isspace(*ptr)) {
                                grad_log(GRAD_LOG_ERR,
				         "%s:%d: %s",
                                         sqlfile, line_no,
				         _("number parse error"));
                                new_cfg.active[SQL_ACCT] = 0;
                                new_cfg.active[SQL_AUTH] = 0;
                        }
                        break;
                        
                case STMT_LOGIN:
                        new_cfg.login = grad_estrdup(cur_ptr);
                        break;
                        
                case STMT_PASSWORD:
                        new_cfg.password = grad_estrdup(cur_ptr);
                        break;
                        
                case STMT_KEEPOPEN:
                        if (get_boolean(cur_ptr, &new_cfg.keepopen))
                                grad_log(GRAD_LOG_ERR,
                                         "%s:%d: %s",
                                         sqlfile, line_no,
				         _("expected boolean value"));
                        break;

                case STMT_IDLE_TIMEOUT:
                        timeout = strtol(cur_ptr, &ptr, 0);
                        if ((*ptr != 0 && !isspace(*ptr)) || timeout <= 0) {
                                grad_log(GRAD_LOG_ERR, "%s:%d: %s",
                                         sqlfile, line_no,
				         _("number parse error"));
                        } else 
                                new_cfg.idle_timeout = timeout;
                        break;
                        
                case STMT_DOAUTH:       
                        if (get_boolean(cur_ptr, &new_cfg.active[SQL_AUTH]))
                                grad_log(GRAD_LOG_ERR,
                                         "%s:%d: %s",
                                         sqlfile, line_no,
				         _("expected boolean value"));
                        break;
                        
                case STMT_DOACCT:
                        if (get_boolean(cur_ptr, &new_cfg.active[SQL_ACCT]))
                                grad_log(GRAD_LOG_ERR,
                                         "%s:%d: %s", 
                                         sqlfile, line_no,
				         _("expected boolean value"));
                        break;
                        
                case STMT_AUTH_DB:
                        new_cfg.auth_db = grad_estrdup(cur_ptr);
                        break;

                case STMT_ACCT_DB:
                        new_cfg.acct_db = grad_estrdup(cur_ptr);
                        break;
                        
                case STMT_MAX_AUTH_CONNECTIONS:
                        grad_log(GRAD_LOG_WARN,
                                 "%s:%d: %s",
                                 sqlfile, line_no,
			         _("auth_max_connections is obsolete"));
                        break;
                        
                case STMT_MAX_ACCT_CONNECTIONS:
                        grad_log(GRAD_LOG_WARN,
                                 "%s:%d: %s",
                                 sqlfile, line_no,
			         _("acct_max_connections is obsolete"));
                        break;
                        
                case STMT_QUERY_BUFFER_SIZE:
                        grad_log(GRAD_LOG_WARN,
			         "%s:%d: %s",
			         sqlfile, line_no,
			         _("query_buffer_size is obsolete"));
                        break;
                        
                case STMT_INTERFACE:
                        new_cfg.interface = disp_sql_interface_index(cur_ptr);
                        if (!new_cfg.interface) {
                                grad_log(GRAD_LOG_WARN, "%s:%d: %s",
                                         sqlfile, line_no,
				         _("Unsupported SQL interface"));
                        }
                        break;

		default:
			if (STMT_QUERY_P(stmt_type)) {
				new_cfg.query[STMT_QUERY_CODE(stmt_type)]
					       = grad_estrdup(cur_ptr);
			} 			
                }
                
        }

        obstack_free(&parse_stack, NULL);
        fclose(sqlfd);

        sql_check_config(sqlfile, &new_cfg);
        grad_free(sqlfile);

        if (!sql_cfg_empty_p(&sql_cfg)
	    && sql_cfg_comp(&new_cfg, &sql_cfg)) 
                sql_flush();

        /* Free old configuration structure */
        FREE(sql_cfg.server);
        FREE(sql_cfg.login);
        FREE(sql_cfg.password);
        FREE(sql_cfg.acct_db) ;
        FREE(sql_cfg.auth_db);
	for (i = 0; i < num_radius_sql_query; i++)
		FREE(sql_cfg.query[i]);
	
        /* copy new config */
        sql_cfg = new_cfg;
                
        return 0;
}

void
radiusd_sql_clear_cache()
{
	sql_cache_destroy(sql_conn[SQL_AUTH]);
	sql_cache_destroy(sql_conn[SQL_ACCT]);
}

void
radiusd_sql_shutdown()
{
	sql_conn_destroy(&sql_conn[SQL_AUTH]);
	sql_conn_destroy(&sql_conn[SQL_ACCT]);
}

static void
missing_statement(int prio, const char *filename, char *stmt)
{
	grad_log(prio, _("%s: missing `%s' statement"),
	         filename, stmt);
}

void
sql_check_config(const char *filename, SQL_cfg *cfg)
{
	int doauth = cfg->active[SQL_AUTH];
	int doacct = cfg->active[SQL_ACCT];

#define FREE_IF_EMPTY(s) if (s && strcmp(s, "none") == 0) {\
                                grad_free(s);\
                                s = NULL;\
                         }

	/* Check general SQL setup */
	if (cfg->active[SQL_AUTH] || cfg->active[SQL_ACCT]) {
		if (disp_sql_interface_index(NULL) == 0) {
			grad_log(GRAD_LOG_ERR, _("%s: SQL interface not specified"),
				 filename);
			doacct = doauth = 0;
		}

		if (!cfg->server) {
			missing_statement(GRAD_LOG_ERR, filename, "server");
			doacct = doauth = 0;
		}

		if (!cfg->login) {
			missing_statement(GRAD_LOG_ERR, filename, "login");
			doacct = doauth = 0;
		}

		if (!cfg->password) {
			missing_statement(GRAD_LOG_ERR, filename, "password");
			doacct = doauth = 0;
		}
	}
	
	/* Check SQL authentication setup */
        if (cfg->active[SQL_AUTH]) {
		if (!cfg->auth_db) {
			missing_statement(GRAD_LOG_ERR, filename, "auth_db");
			doauth = 0;
		}

		FREE_IF_EMPTY(cfg->query[auth_query]);
		if (!cfg->query[auth_query]) {
			missing_statement(GRAD_LOG_ERR, filename, "auth_query");
			doauth = 0;
		}
			 
		if (!cfg->query[group_query]) 
			missing_statement(GRAD_LOG_WARN, filename, "group_query");
                FREE_IF_EMPTY(cfg->query[group_query]);
        }

	/* Check SQL accounting setup */
        if (cfg->active[SQL_ACCT]) {
		if (!cfg->acct_db) {
			missing_statement(GRAD_LOG_ERR, filename, "acct_db");
			doacct = 0;
		}
                if (!cfg->query[acct_start_query]) 
			missing_statement(GRAD_LOG_WARN, filename,
					  "acct_start_query");
                FREE_IF_EMPTY(cfg->query[acct_start_query]);

		if (!cfg->query[acct_stop_query]) {
			missing_statement(GRAD_LOG_ERR, filename, "acct_stop_query");
			doacct = 0;
		}
		FREE_IF_EMPTY(cfg->query[acct_stop_query]);

                if (!cfg->query[acct_nasdown_query]) 
			missing_statement(GRAD_LOG_WARN, filename,
					  "acct_nasdown_query");
                FREE_IF_EMPTY(cfg->query[acct_nasdown_query]);

                if (!cfg->query[acct_nasup_query])
			missing_statement(GRAD_LOG_WARN, filename,
					  "acct_nasup_query");
                FREE_IF_EMPTY(cfg->query[acct_nasup_query]);
        }

	/* Inform the user */
	if (cfg->active[SQL_AUTH] != doauth)
		grad_log(GRAD_LOG_NOTICE, _("disabling SQL authentication"));
	if (cfg->active[SQL_ACCT] != doacct)
		grad_log(GRAD_LOG_NOTICE, _("disabling SQL accounting"));
}

void
sql_flush()
{
        grad_log(GRAD_LOG_NOTICE,
                 _("SQL configuration changed: closing existing connections"));
        radiusd_flush_queue();
	radiusd_sql_shutdown();
}


/* ********************************* SQL Cache ***************************** */
static void
sql_result_destroy(SQL_RESULT *res)
{
	size_t i;
	
	if (!res)
		return;
	grad_free(res->query);
	for (i = 0; i < res->ntuples; i++) {
		size_t j;
		for (j = 0; j < res->nfields; j++) 
			grad_free(res->tuple[i][j]);
		grad_free(res->tuple[i]);
	}
	grad_free(res->tuple);
	grad_free(res);
}

static size_t
sql_cache_level(struct sql_connection *conn)
{
	if (conn->tail < conn->head)
		return conn->tail + SQL_CACHE_SIZE - conn->head;
	else
		return conn->tail - conn->head;
}

static void
sql_cache_destroy(struct sql_connection *conn)
{
	size_t i;

	if (!conn)
		return;
	for (; sql_cache_level(conn) > 0;
	     conn->head = (conn->head + 1) % SQL_CACHE_SIZE)
		sql_result_destroy(conn->cache[conn->head]);
}

static void
sql_cache_insert(struct sql_connection *conn, SQL_RESULT *res)
{
	GRAD_DEBUG3(20, "cache: %d,(%d,%d)",
	            sql_cache_level(conn),conn->head,conn->tail);
	if (sql_cache_level(conn) >= SQL_CACHE_SIZE-1) {
		sql_result_destroy(conn->cache[conn->head]);
		conn->head = (conn->head + 1) % SQL_CACHE_SIZE;
	        GRAD_DEBUG2(20,"head: %d,%d", conn->head,conn->tail);
	}
	GRAD_DEBUG1(20,"inserting at pos %d", conn->tail);
	conn->cache[conn->tail] = res;
	conn->tail = (conn->tail + 1) % SQL_CACHE_SIZE;
	GRAD_DEBUG2(20,"tail: %d,%d", conn->head,conn->tail);
}

static SQL_RESULT *
sql_cache_retrieve(struct sql_connection *conn, char *query)
{
        void *data;
	SQL_RESULT *res;
	size_t i;
	
	GRAD_DEBUG1(20,"query: %s",query);
	res = grad_emalloc(sizeof(*res));
	res->query = grad_estrdup(query);
	res->nfields = res->ntuples = 0;
	res->tuple = NULL;
        data = disp_sql_exec(conn, query);
        if (!data) {
		sql_cache_insert(conn, res);
                return res;
	}
	
	if (disp_sql_num_tuples(conn, data, &res->ntuples)
	    || disp_sql_num_columns(conn, data, &res->nfields)) {
		disp_sql_free(conn, data);
		res->nfields = res->ntuples = 0;
		sql_cache_insert(conn, res);
		return res;
	}

	res->tuple = grad_emalloc(sizeof(res->tuple[0]) * res->ntuples);
        for (i = 0; i < res->ntuples
		     && disp_sql_next_tuple(conn, data) == 0; i++) {
		int j;

		res->tuple[i] = grad_emalloc(sizeof(res->tuple[0][0]) * res->nfields);
			
		for (j = 0; j < res->nfields; j++) {
			char *p = disp_sql_column(conn, data, j);
			chop(p);
			res->tuple[i][j] = grad_estrdup(p);
		}
	}
		
        disp_sql_free(conn, data);

	sql_cache_insert(conn, res);
	
        return res;
}

static SQL_RESULT *
sql_cache_lookup(struct sql_connection *conn, char *query)
{
	size_t i;

	GRAD_DEBUG1(20,"looking up %s", query);
	for (i = conn->head; i != conn->tail;
	     i = (i + 1) % SQL_CACHE_SIZE) {
		if (strcmp(conn->cache[i]->query, query) == 0) {
			GRAD_DEBUG1(20,"found at %d", i);
			return conn->cache[i];
		}
	}
	GRAD_DEBUG(20,"NOT FOUND");
	return NULL;
}


/* *********************** SQL Connection Handling ************************* */

struct sql_connection *
attach_sql_connection(int type)
{
        struct sql_connection *conn;
        time_t now;
        
        time(&now);
        conn = sql_conn[type];
        if (!conn) {
                GRAD_DEBUG1(1, "allocating new %d sql connection", type);

                conn = grad_emalloc(sizeof(struct sql_connection));
		conn->cfg = &sql_cfg;
		conn->connected = 0;
                conn->last_used = now;
                conn->type = type;

		conn->head = 0;
		conn->tail = 0;
                sql_conn[type] = conn;
        }

        if (!conn->connected || now - conn->last_used > sql_cfg.idle_timeout) {
                GRAD_DEBUG1(1, "connection %d timed out: reconnect", type);
                disp_sql_reconnect(sql_cfg.interface, type, conn);
        }
	conn->destroy_on_close = !sql_cfg.keepopen;
        conn->last_used = now;
        GRAD_DEBUG2(1, "attaching %p [%d]", conn, type);
        return conn;
}

void
detach_sql_connection(int type)
{
        struct sql_connection *conn;

        conn = sql_conn[type];
        if (!conn)
                return;
        GRAD_DEBUG2(1, "detaching %p [%d]", conn, type);
        if (conn->destroy_on_close) {
                GRAD_DEBUG1(1, "destructing sql connection %p", conn);
		sql_conn_destroy(&sql_conn[type]);
        }
}

static void
sql_conn_destroy(struct sql_connection **conn)
{
	if (*conn) {
	        if ((*conn)->connected)
		        disp_sql_disconnect(*conn);
		sql_cache_destroy(*conn);
		grad_free(*conn);
		*conn = NULL;
	}
}


/* ************************* Interface Functions *************************** */

/*ARGSUSED*/
void
radiusd_sql_cleanup(int type, void *req ARG_UNUSED)
{
        if (sql_cfg.active[type])
                detach_sql_connection(type);
}

/*
 * Perform normal accounting
 */ 
void
radiusd_sql_acct(radiusd_request_t *radreq)
{
        int rc, count;
        int status;
        grad_avp_t *pair;
        char *query;
        struct sql_connection *conn;
        struct obstack stack;
        char *query_name;
	int log_facility = 0;
	
        if (!sql_cfg.active[SQL_ACCT])
                return;

        if (!(pair = grad_avl_find(radreq->request->avlist,
				   DA_ACCT_STATUS_TYPE))) {
                /* should never happen!! */
                grad_log_req(GRAD_LOG_ERR, radreq->request,
                             _("no Acct-Status-Type attribute in rad_sql_acct()"));
                return;
        }
        status = pair->avp_lvalue;

        conn = attach_sql_connection(SQL_ACCT);
        obstack_init(&stack);

        switch (status) {
        case DV_ACCT_STATUS_TYPE_START:
		query_name = "acct_start_query";
                if (!sql_cfg.query[acct_start_query])
                        break;
                query = radius_xlate(&stack,
                                     sql_cfg.query[acct_start_query],
                                     radreq->request, NULL);
                rc = disp_sql_query(conn, query, NULL);
                sqllog(rc, query);
		log_facility = 0;
                break;
                
        case DV_ACCT_STATUS_TYPE_STOP:
		query_name = "acct_stop_query";
                if (!sql_cfg.query[acct_stop_query])
                        break;
                query = radius_xlate(&stack,
                                     sql_cfg.query[acct_stop_query],
                                     radreq->request, NULL);
                rc = disp_sql_query(conn, query, &count);
                sqllog(rc, query);
                if (rc == 0 && count != 1) 
			log_facility = GRAD_LOG_WARN;
                break;

        case DV_ACCT_STATUS_TYPE_ACCOUNTING_ON:
		query_name = "acct_nasup_query";
                if (!sql_cfg.query[acct_nasup_query])
                        break;
                query = radius_xlate(&stack,
                                     sql_cfg.query[acct_nasup_query],
                                     radreq->request, NULL);
                rc = disp_sql_query(conn, query, &count);
                sqllog(rc, query);
		if (rc == 0)
			log_facility = GRAD_LOG_INFO;
                break;

        case DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF:
		query_name = "acct_nasdown_query";
                if (!sql_cfg.query[acct_nasdown_query])
                        break;
                query = radius_xlate(&stack,
                                     sql_cfg.query[acct_nasdown_query],
                                     radreq->request, NULL);
                rc = disp_sql_query(conn, query, &count);
                sqllog(rc, query);
		if (rc == 0)
			log_facility = GRAD_LOG_INFO;
                break;

        case DV_ACCT_STATUS_TYPE_ALIVE:
		query_name = "acct_keepalive_query";
                if (!sql_cfg.query[acct_keepalive_query])
                        break;
                query = radius_xlate(&stack,
                                     sql_cfg.query[acct_keepalive_query],
                                     radreq->request, NULL);
                rc = disp_sql_query(conn, query, &count);
                sqllog(rc, query);
                if (rc == 0 && count != 1) 
			log_facility = GRAD_LOG_WARN;
                break;
                
        }

	if (log_facility) {
		grad_log_req(log_facility, radreq->request,
			     ngettext("%s updated %d record",
				      "%s updated %d records",
				      count),
			     query_name,
			     count);
	}

        obstack_free(&stack, NULL);
}


char *
radiusd_sql_pass(radiusd_request_t *req, char *authdata)
{
        char *mysql_passwd;
        struct sql_connection *conn;
        char *query;
        struct obstack stack;
        
        if (sql_cfg.active[SQL_AUTH] == 0) {
                grad_log(GRAD_LOG_ERR,
                         _("SQL Auth specified in users file, but not in sqlserver file"));
                return NULL;
        }
        
        if (authdata) {
                grad_avl_add_pair(&req->request->avlist,
				  grad_avp_create_string(DA_AUTH_DATA,
							 authdata));
        }
        
        obstack_init(&stack);
        query = radius_xlate(&stack, sql_cfg.query[auth_query],
			     req->request, NULL);
        grad_avl_delete(&req->request->avlist, DA_AUTH_DATA);
        
        conn = attach_sql_connection(SQL_AUTH);
        mysql_passwd = disp_sql_getpwd(conn, query);
	
        if (mysql_passwd) 
                chop(mysql_passwd);
        
        obstack_free(&stack, NULL);
        
        return mysql_passwd;
}

int
radiusd_sql_checkgroup(radiusd_request_t *req, char *groupname)
{
        int   rc = -1;
        struct sql_connection *conn;
        char *query;
        struct obstack stack;
	SQL_RESULT *res;
	size_t i;
	
        if (sql_cfg.active[SQL_AUTH] == 0 || !sql_cfg.query[group_query]) 
                return -1;

        conn = attach_sql_connection(SQL_AUTH);
        if (!conn)
                return -1;

        obstack_init(&stack);
	
        query = radius_xlate(&stack, sql_cfg.query[group_query],
			     req->request, NULL);
	res = sql_cache_lookup(conn, query);
	if (!res) {
		res = sql_cache_retrieve(conn, query);
		if (!res) {
			obstack_free(&stack, NULL);
			return -1;
		}
	}
        obstack_free(&stack, NULL);

	if (res->ntuples == 0 || res->nfields == 0)
		return rc;

	for (i = 0; rc != 0 && i < res->ntuples; i++) {
		if (strcmp(res->tuple[i][0], groupname) == 0)
			rc = 0;
	}
	
        return rc;
}

static int
rad_sql_retrieve_pairs(struct sql_connection *conn,
		       char *query,
		       grad_avp_t **return_pairs,
		       int op_too)
{
	SQL_RESULT *res;
	size_t i;
	grad_locus_t loc;
	
	res = sql_cache_lookup(conn, query);
	if (!res) {
		res = sql_cache_retrieve(conn, query);
		if (!res)
			return 0;
	}

	if (res->ntuples == 0
	    || res->nfields < 2
	    || (op_too && res->nfields < 3))
		return 0;
	
        for (i = 0; i < res->ntuples; i++) {
		enum grad_operator op;
		grad_avp_t *pair;
		
		if (op_too) {
			char *opstr = res->tuple[i][2];
                        op = grad_str_to_op(opstr);
                        if (op == grad_operator_invalid) {
                                grad_log(GRAD_LOG_NOTICE,
                                         _("SQL: invalid operator: %s"), opstr);
                                continue;
                        }
		} else
			op = grad_operator_equal;

		loc.file = __FILE__;
		loc.line = __LINE__;
                pair = grad_create_pair(&loc,
					res->tuple[i][0],
					op,
					res->tuple[i][1]);
                
                if (pair) {
                        grad_avl_merge(return_pairs, &pair);
                        grad_avl_free(pair);
                }
	}		

	return i;
}
			
int
radiusd_sql_reply_attr_query(radiusd_request_t *req, grad_avp_t **reply_pairs)
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
        
        if (sql_cfg.active[SQL_AUTH] == 0 || !sql_cfg.query[reply_attr_query])
                return 0;
        
        conn = attach_sql_connection(SQL_AUTH);
        obstack_init(&stack);

        query = radius_xlate(&stack, sql_cfg.query[reply_attr_query],
			     req->request, NULL);
        rc = rad_sql_retrieve_pairs(conn, query, reply_pairs, 0);

        obstack_free(&stack, NULL);
        return rc == 0;
}

int
radiusd_sql_check_attr_query(radiusd_request_t *req, grad_avp_t **return_pairs)
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
        
        if (sql_cfg.active[SQL_AUTH] == 0 || !sql_cfg.query[check_attr_query])
                return 0;
        
        conn = attach_sql_connection(SQL_AUTH);
        obstack_init(&stack);
	
        query = radius_xlate(&stack, sql_cfg.query[check_attr_query],
			     req->request, NULL);
        rc = rad_sql_retrieve_pairs(conn, query, return_pairs, 1);
        
        obstack_free(&stack, NULL);
        return rc == 0;
}

int
sql_auth_avail_p(const char **msg)
{
	if (sql_cfg.active[SQL_AUTH] && sql_cfg.query[auth_query])
		return 1;
	*msg = _("SQL authentication is not enabled in raddb/sqlserver");
	return 0;
}


/* ****************************************************************************
 * Auth failure trigger
 */
void
radiusd_sql_auth_result_query(radiusd_request_t *req, int fail)
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
	enum radius_sql_query q = fail ? auth_failure_query : auth_success_query;
	
	if (!sql_cfg.active[SQL_AUTH] || !sql_cfg.query[q])
		return;

        conn = attach_sql_connection(SQL_AUTH);
        obstack_init(&stack);
	
        query = radius_xlate(&stack, sql_cfg.query[q],
			     req->request, NULL);
	rc = disp_sql_query(conn, query, NULL);
	sqllog(rc, query);
        obstack_free(&stack, NULL);
}


/* ****************************************************************************
 * Multiple login checking
 */

static int
rad_sql_retrieve_sessions(struct sql_connection *conn,
			  char *query,
			  grad_list_t **sess_list)
{
	SQL_RESULT *res;
	size_t i;
	grad_locus_t loc;
	struct radutmp utmp;
	
	res = sql_cache_lookup(conn, query);
	if (!res) {
		res = sql_cache_retrieve(conn, query);
		if (!res)
			return 0;
	}

	if (res->ntuples == 0 || res->nfields != 4)
		return 0;
	
        for (i = 0; i < res->ntuples; i++) {
		struct radutmp *up = grad_emalloc(sizeof(*up));
		GRAD_STRING_COPY(up->login, res->tuple[i][0]);
		GRAD_STRING_COPY(up->orig_login, res->tuple[i][0]);
		up->nas_address = htonl(grad_ip_strtoip(res->tuple[i][1]));
		up->nas_port = strtoul(res->tuple[i][2], NULL, 0);
		GRAD_STRING_COPY(up->session_id, res->tuple[i][3]);
		if (*sess_list == NULL) 
			*sess_list = grad_list_create();
		grad_list_append(*sess_list, up);
	}		

	return i;
}

int
sql_mlc_collect(const char *query_template,
		radiusd_request_t *request,
		grad_list_t **sess_list)
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
        
        conn = attach_sql_connection(SQL_ACCT);
        obstack_init(&stack);
	
        query = radius_xlate(&stack, (char*) query_template,
			     request->request, NULL);
        rc = rad_sql_retrieve_sessions(conn, query, sess_list);
	obstack_free(&stack, NULL);
        return rc == 0;
}

int
rad_sql_mlc_enabled_p()
{
	return sql_cfg.active[SQL_ACCT]
		&& sql_cfg.query[mlc_user_query];
}

int
rad_sql_mlc_collect_user(char *name, radiusd_request_t *request,
			 grad_list_t **sess_list)
{
        if (sql_cfg.active[SQL_ACCT] == 0 || !sql_cfg.query[mlc_user_query])
                return 1;
	return sql_mlc_collect(sql_cfg.query[mlc_user_query],
			       request, sess_list);
}

int
rad_sql_mlc_collect_realm(radiusd_request_t *request, grad_list_t **sess_list)
{
        if (sql_cfg.active[SQL_ACCT] == 0 || !sql_cfg.query[mlc_realm_query])
                return 1;
	return sql_mlc_collect(sql_cfg.query[mlc_realm_query],
			       request, sess_list);
}

void
rad_sql_mlc_close(struct radutmp *up)
{
	int query_index = sql_cfg.query[mlc_stop_query] ?
		                  mlc_stop_query : acct_stop_query;
	char *query;
	struct obstack stack;
	grad_request_t *req;
	int rc;
	size_t count;
	struct sql_connection *conn;
	
	if (sql_cfg.active[SQL_ACCT] == 0 || !sql_cfg.query[query_index])
		return;
	conn = attach_sql_connection(SQL_ACCT);
	obstack_init(&stack);
	/* Create a temporary request */
	req = grad_request_alloc();
	grad_avl_add_pair(&req->avlist,
			  grad_avp_create_string(DA_USER_NAME, up->orig_login));
	grad_avl_add_pair(&req->avlist,
			  grad_avp_create_integer(DA_NAS_PORT_ID,
						  up->nas_port));
	grad_avl_add_pair(&req->avlist,
			  grad_avp_create_integer(DA_NAS_IP_ADDRESS,
						  ntohl(up->nas_address)));
	grad_avl_add_pair(&req->avlist,
			  grad_avp_create_string(DA_ACCT_SESSION_ID,
						 up->session_id));
	query = radius_xlate(&stack, sql_cfg.query[query_index], req, NULL);
	grad_request_free(req);
	rc = disp_sql_query(conn, query, &count);
	sqllog(rc, query);
	if (rc == 0 && count != 1) {
		grad_log(GRAD_LOG_WARN,
			 ngettext("%s updated %d record",
				  "%s updated %d records",
				  count),
			 sql_query_name(query_index),
			 count);
	}
	obstack_free(&stack, NULL);
}


void
sql_init()
{
	mlc_register_method("sql",
			    rad_sql_mlc_collect_user,
			    rad_sql_mlc_collect_realm,
			    rad_sql_mlc_close,
			    rad_sql_mlc_enabled_p);
	disp_init();
}


/* ****************************************************************************
 * Guile interface
 */
#ifdef USE_SERVER_GUILE

SCM
sql_exec_query(int type, const char *query)
{
	int i, j;
        struct sql_connection *conn;
	void *data;
	SCM row_head = SCM_EOL, row_tail;
	
	if (type < 0 || type > SQL_NSERVICE)
		return SCM_BOOL_F;
	conn = attach_sql_connection(type);
        data = disp_sql_exec(conn, query);
        if (!data) 
                return SCM_BOOL_F;
	
	for (i = 0; disp_sql_next_tuple(conn, data) == 0; i++) {
		char *tuple;
		SCM new_row;
		SCM head = SCM_EOL, tail;
		
		for (j = 0; tuple = disp_sql_column(conn, data, j); j++) {
			SCM new_elt = scm_cons(scm_makfrom0str(tuple), SCM_EOL);
			if (head == SCM_EOL)
				head = new_elt;
			else
				SCM_SETCDR(tail, new_elt);
			tail = new_elt;
		}
		new_row = scm_cons(head, SCM_EOL);
		if (row_head == SCM_EOL)
			row_head = new_row;
		else
			SCM_SETCDR(row_tail, new_row);
		row_tail = new_row;
	}
	disp_sql_free(conn, data);
	
	return row_head;
}

SCM
sql_run_query(int type, const char *query)
{
	int rc;
        struct sql_connection *conn;
	int count;
	SCM res;
	
	if (type < 0 || type > SQL_NSERVICE)
		return SCM_BOOL_F;
	conn = attach_sql_connection(type);
	rc = disp_sql_query(conn, query, &count);
	if (rc)
                return SCM_BOOL_F;
	return scm_from_long(count);
}
#endif

#else

int
sql_auth_avail_p(const char **msg)
{
	*msg = _("Radiusd is compiled without SQL support");
	return 0;
}

#endif
