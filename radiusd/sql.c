/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_SQL_C
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
static struct sql_connection *attach_sql_connection(int type, RADIUS_REQ *req);
static void detach_sql_connection(int type, RADIUS_REQ *req);

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
#define STMT_REPLY_ATTR_QUERY            21
#define STMT_INTERFACE             22
#define STMT_CHECK_ATTR_QUERY      23

static FILE  *sqlfd;
static int line_no;
static char *cur_line, *cur_ptr;
static struct obstack parse_stack;
static int stmt_type;

static pthread_key_t sql_conn_key[SQL_NSERVICE];
static pthread_once_t sql_conn_key_once = PTHREAD_ONCE_INIT;

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
        "attr_query",         STMT_REPLY_ATTR_QUERY,
        "reply_attr_query",   STMT_REPLY_ATTR_QUERY,
        "check_attr_query",   STMT_CHECK_ATTR_QUERY,
        "acct_start_query",   STMT_ACCT_START_QUERY,
        "acct_stop_query",    STMT_ACCT_STOP_QUERY,
        "acct_alive_query",   STMT_ACCT_KEEPALIVE_QUERY,
        "acct_keepalive_query", STMT_ACCT_KEEPALIVE_QUERY,
        "acct_nasup_query",   STMT_ACCT_NASUP_QUERY,
        "acct_nasdown_query", STMT_ACCT_NASDOWN_QUERY,
        "interface",          STMT_INTERFACE,
        NULL,
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

static void
sql_conn_destroy(void *data)
{
        if (data) {
                struct sql_connection *conn = data;
                if (conn->connected)
                        disp_sql_disconnect(sql_cfg.interface, conn);
                free_entry(conn);
        }
}

static void
sql_conn_key_alloc()
{
        pthread_key_create(&sql_conn_key[SQL_AUTH], sql_conn_destroy);
        pthread_key_create(&sql_conn_key[SQL_ACCT], sql_conn_destroy);
}

int 
rad_sql_init()
{
        char *sqlfile;
        UINT4 ipaddr;
        char *ptr;
        time_t timeout;
        SQL_cfg new_cfg;

        pthread_once(&sql_conn_key_once, sql_conn_key_alloc);
        
#define FREE(a) if (a) efree(a); a = NULL

        bzero(&new_cfg, sizeof(new_cfg));
        new_cfg.keepopen = 0;
        new_cfg.idle_timeout = 4*3600; /* four hours */
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
        obstack_init(&parse_stack);
        while (getline()) {
                if (stmt_type == -1) {
                        radlog(L_ERR,
                               "%s:%d: %s",
                               sqlfile, line_no,
			       _("unrecognized keyword"));
                        continue;
                }
                /* Each keyword should have an argument */
                if (cur_ptr == NULL) {
                        radlog(L_ERR,
                               "%s:%d: %s",
                               sqlfile, line_no,
			       _("required argument missing"));
                        continue;
                }
                
                switch (stmt_type) {
                case STMT_SERVER:
                        ipaddr = ip_gethostaddr(cur_ptr);
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
                                radlog(L_ERR,
				       "%s:%d: %s",
                                       sqlfile, line_no,
				       _("number parse error"));
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
                                       "%s:%d: %s",
                                       sqlfile, line_no,
				       _("expected boolean value"));
                        break;

                case STMT_IDLE_TIMEOUT:
                        timeout = strtol(cur_ptr, &ptr, 0);
                        if ((*ptr != 0 && !isspace(*ptr)) || timeout <= 0) {
                                radlog(L_ERR, "%s:%d: %s",
                                       sqlfile, line_no,
				       _("number parse error"));
                        } else 
                                new_cfg.idle_timeout = timeout;
                        break;
                        
                case STMT_DOAUTH:       
                        if (get_boolean(cur_ptr, &new_cfg.doauth))
                                radlog(L_ERR,
                                       "%s:%d: %s",
                                       sqlfile, line_no,
				       _("expected boolean value"));
                        break;
                        
                case STMT_DOACCT:
                        if (get_boolean(cur_ptr, &new_cfg.doacct))
                                radlog(L_ERR,
                                       "%s:%d: %s", 
                                       sqlfile, line_no,
				       _("expected boolean value"));
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
                        
                case STMT_REPLY_ATTR_QUERY:
                        new_cfg.reply_attr_query = estrdup(cur_ptr);
                        break;

                case STMT_CHECK_ATTR_QUERY:
                        new_cfg.check_attr_query = estrdup(cur_ptr);
                        break;
                        
                case STMT_MAX_AUTH_CONNECTIONS:
                        radlog(L_WARN,
                               "%s:%d: %s",
                               sqlfile, line_no,
			       _("auth_max_connections is obsolete"));
                        break;
                        
                case STMT_MAX_ACCT_CONNECTIONS:
                        radlog(L_WARN,
                               "%s:%d: %s",
                               sqlfile, line_no,
			       _("acct_max_connections is obsolete"));
                        break;
                        
                case STMT_QUERY_BUFFER_SIZE:
                        radlog(L_WARN,
			       "%s:%d: %s",
			       sqlfile, line_no,
			       _("query_buffer_size is obsolete"));
                        break;
                        
                case STMT_INTERFACE:
                        new_cfg.interface = disp_sql_interface_index(cur_ptr);
                        if (!new_cfg.interface) {
                                radlog(L_WARN, "%s:%d: %s",
                                       sqlfile, line_no,
				       _("Unsupported SQL interface"));
                        }
                        break;
                }
                
        }

        obstack_free(&parse_stack, NULL);

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
        FREE(sql_cfg.reply_attr_query);
        FREE(sql_cfg.check_attr_query);
        
        /* copy new config */
        sql_cfg = new_cfg;
                
        return 0;
}

void
rad_sql_shutdown()
{
        /*FIXME*/
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


void
sql_flush()
{
        radlog(L_NOTICE,
               _("SQL configuration changed: closing existing connections"));
        rad_flush_queues();
}

/*FIXME: radreq not needed */
struct sql_connection *
attach_sql_connection(type, radreq)
        int type;
        RADIUS_REQ *radreq;
{
        struct sql_connection *conn;
        time_t now;
        
        time(&now);
        conn = pthread_getspecific(sql_conn_key[type]);
        if (!conn) {
                debug(1, ("allocating new %d sql connection", type));

                conn = alloc_entry(sizeof(struct sql_connection));
                conn->owner = NULL;
                conn->delete_on_close = !sql_cfg.keepopen;
                conn->connected = 0;
                conn->last_used = now;
                conn->type = type;

                pthread_setspecific(sql_conn_key[type], conn);
        }

        if (!conn->connected || now - conn->last_used > sql_cfg.idle_timeout) {
                debug(1, ("connection %d timed out: reconnect", type));
                disp_sql_reconnect(sql_cfg.interface, type, conn);
        }
        conn->last_used = now;
        debug(1, ("attaching %p->%p [%d]", radreq, conn, type));
        return conn;
}

/*FIXME: radreq not needed */
void
detach_sql_connection(type, radreq)
        int type;
        RADIUS_REQ *radreq;
{
        struct sql_connection *conn;

        conn = pthread_getspecific(sql_conn_key[type]);
        if (!conn)
                return;
        debug(1, ("detaching %p->%p [%d]", radreq, conn, type));
        if (conn->delete_on_close) {
                debug(1, ("destructing sql connection %p",
                          conn));
                if (conn->connected)
                        disp_sql_disconnect(sql_cfg.interface, conn);
                free_entry(conn);
                pthread_setspecific(sql_conn_key[type], NULL);
        }
}

void
rad_sql_cleanup(type, req)
        int type;
        RADIUS_REQ *req;
{
        if (sql_cfg.active[type])
                detach_sql_connection(type, req);
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
        struct obstack stack;
        
        if (!sql_cfg.doacct)
                return;

        if ((pair = avl_find(radreq->request, DA_ACCT_STATUS_TYPE)) == NULL) {
                /* should never happen!! */
                radlog_req(L_ERR, radreq,
                           _("no Acct-Status-Type attribute in rad_sql_acct()"));
                return ;
        }
        status = pair->lvalue;

        conn = attach_sql_connection(SQL_ACCT, radreq);
        obstack_init(&stack);
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
                        radlog_req(L_WARN, radreq,
                                   _("acct_stop_query: %d rows changed"),
                                   count);
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
                        radlog_req(L_INFO, radreq,
                                   _("acct_nasup_query updated %d records"),
                                   count);
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
                        radlog_req(L_INFO, radreq,
                                   _("acct_nasdown_query updated %d records"),
                                   count);
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
                        radlog_req(L_INFO, radreq,
                                   _("acct_keepalive_query updated %d records"),
                                   count);
                }
                break;
                
        }

        obstack_free(&stack, NULL);
}


char *
rad_sql_pass(req, authdata)
        RADIUS_REQ *req;
        char *authdata;
{
        char *mysql_passwd;
        struct sql_connection *conn;
        char *query;
        struct obstack stack;
        
        if (sql_cfg.doauth == 0) {
                radlog(L_ERR,
                       _("SQL Auth specified in users file, but not in sqlserver file"));
                return NULL;
        }
        
        if (authdata) {
                avl_add_pair(&req->request,
                             avp_create(DA_AUTH_DATA,
                                        strlen(authdata),
                                        authdata, 0));
        }
        
        obstack_init(&stack);
        query = radius_xlate(&stack, sql_cfg.auth_query, req, NULL);
        avl_delete(&req->request, DA_AUTH_DATA);
        
        conn = attach_sql_connection(SQL_AUTH, req);
        mysql_passwd = disp_sql_getpwd(sql_cfg.interface, conn, query);
        
        if (mysql_passwd) 
                chop(mysql_passwd);
        
        obstack_free(&stack, NULL);
        
        return mysql_passwd;
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
        struct obstack stack;
        
        if (sql_cfg.doauth == 0 || sql_cfg.group_query == NULL) 
                return -1;

        conn = attach_sql_connection(SQL_AUTH, req);
        if (!conn)
                return -1;

        obstack_init(&stack);
        query = radius_xlate(&stack, sql_cfg.group_query, req, NULL);

        data = disp_sql_exec(sql_cfg.interface, conn, query);
        while (rc != 0
               && disp_sql_next_tuple(sql_cfg.interface, conn, data) == 0) {
                if ((p = disp_sql_column(sql_cfg.interface, data, 0)) == NULL)
                        break;
                chop(p);
                if (strcmp(p, groupname) == 0)
                        rc = 0;
        }
        disp_sql_free(sql_cfg.interface, conn, data);
        
        obstack_free(&stack, NULL);
        return rc;
}

static int rad_sql_retrieve_pairs(struct sql_connection *conn,
                                  char *query,
                                  VALUE_PAIR **return_pairs,
                                  int op_too);

int
rad_sql_retrieve_pairs(conn, query, return_pairs, op_too)
        struct sql_connection *conn;
        char *query;
        VALUE_PAIR **return_pairs;
        int op_too;
{
        void *data;
        int i;
        
        data = disp_sql_exec(sql_cfg.interface, conn, query);
        if (!data)
                return 0;
        
        for (i = 0; disp_sql_next_tuple(sql_cfg.interface, conn, data) == 0;
             i++) {
                VALUE_PAIR *pair;
                char *attribute;
                char *value;
                int op;
                
                if (!(attribute = disp_sql_column(sql_cfg.interface, data, 0))
                    || !(value =  disp_sql_column(sql_cfg.interface, data, 1)))
                        break;
                if (op_too) {
                        char *opstr;
                        opstr = disp_sql_column(sql_cfg.interface, data, 2);
                        if (!opstr)
                                break;
                        chop(opstr);
                        op = str_to_op(opstr);
                        if (op == NUM_OPERATORS) {
                                radlog(L_NOTICE,
                                       _("SQL: invalid operator: %s"), opstr);
                                continue;
                        }
                } else
                        op = OPERATOR_EQUAL;

                chop(attribute);
                chop(value);
                
                pair = install_pair(attribute, op, value);
                
                if (pair) {
                        avl_merge(return_pairs, &pair);
                        avl_free(pair);
                }
        }

        disp_sql_free(sql_cfg.interface, conn, data);
        return i;
}

int
rad_sql_reply_attr_query(req, reply_pairs)
        RADIUS_REQ *req;
        VALUE_PAIR **reply_pairs;
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
        
        if (sql_cfg.doauth == 0 || !sql_cfg.reply_attr_query)
                return 0;
        
        conn = attach_sql_connection(SQL_AUTH, req);

        obstack_init(&stack);
        query = radius_xlate(&stack, sql_cfg.reply_attr_query, req, NULL);

        rc = rad_sql_retrieve_pairs(conn, query, reply_pairs, 0);
        
        obstack_free(&stack, NULL);
        return rc == 0;
}

int
rad_sql_check_attr_query(req, return_pairs)
        RADIUS_REQ *req;
        VALUE_PAIR **return_pairs;
{
        struct sql_connection *conn;
        char *query;
        int rc;
        struct obstack stack;
        
        if (sql_cfg.doauth == 0 || !sql_cfg.check_attr_query)
                return 0;
        
        conn = attach_sql_connection(SQL_AUTH, req);

        obstack_init(&stack);
        query = radius_xlate(&stack, sql_cfg.check_attr_query, req, NULL);

        rc = rad_sql_retrieve_pairs(conn, query, return_pairs, 1);
        
        obstack_free(&stack, NULL);
        return rc == 0;
}

#endif
