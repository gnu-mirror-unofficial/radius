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

#define LOG_EMPTY_USERNAME

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <radiusd.h>
#include <radius/radutmp.h>
#include <rewrite.h>

int     doradwtmp = 1;

static int write_wtmp(struct radutmp *ut);
static int write_nas_restart(int status, grad_uint32_t addr);
static int check_ts(struct radutmp *ut);

int rad_acct_system(radiusd_request_t *radreq, int dowtmp);
int rad_acct_db(radiusd_request_t *radreq, int authtype);
int rad_acct_ext(radiusd_request_t *radreq);


/* Zap a user, or all users on a NAS, from the radutmp file. */
int
radzap(grad_uint32_t nasaddr, int port, char *user, time_t t)
{
        struct radutmp  *up;
        radut_file_t    file;
        grad_uint32_t           netaddr;
        
        if (t == 0) time(&t);
        netaddr = htonl(nasaddr);

        if (file = grad_ut_setent(grad_utmp_file, 0)) {
                /* Find the entry for this NAS / portno combination. */
                while (up = grad_ut_getent(file)) {
                        if (((nasaddr != 0 && netaddr != up->nas_address) ||
                             (port >= 0   && port    != up->nas_port) ||
                             (user != NULL && strcmp(up->login, user) != 0) ||
                             up->type != P_LOGIN))
                                continue;
                        /* Zap the entry */
                        up->type = P_IDLE;
                        up->time = t;
                        grad_ut_putent(file, up);
                        /* Add a logout entry to the wtmp file. */
                        write_wtmp(up);
                }
                grad_ut_endent(file);
        }

        return 0;
}

static void
store_session_id(char *buffer, int len, char *id, int idlen)
{
        int off = idlen - len;
        if (off < 0)
                off = 0;
        memcpy(buffer, id + off, len);
        buffer[len-1] = 0;
}

int
write_wtmp(struct radutmp *ut)
{
        return grad_radwtmp_putent(grad_wtmp_file, ut);
}

void
backslashify(char *dst, char *src, int len)
{
#define CHECK(l,m) \
 if (l <= m) goto end; else l -= m
        
#define ESCAPE(c)\
 CHECK(len,2);\
 src++;\
 *dst++ = '\\';\
 *dst++ = c

        while (*src && len > 1) {
                switch (*src) {
                case '\\':
                        ESCAPE('\\');
                        break;
                case '\a':
                        ESCAPE('a');
                        break;
                case '\b':
                        ESCAPE('b');
                        break;
                case '\f':
                        ESCAPE('f');
                        break;
                case '\n':
                        ESCAPE('n');
                        break;
                case '\r':
                        ESCAPE('r');
                        break;
                case '\t':
                        ESCAPE('t');
                        break;
                default:
                        *dst++ = *src++;
                        len--;
                }
        }

end:
        *dst = 0;
}

int
check_attribute(grad_avp_t *check_pairs, int pair_attr,
		int pair_value, int def)
{
        grad_avp_t *pair;

        if ((pair = grad_avl_find(check_pairs, pair_attr)) == NULL)
                return def;
        do {
                if (pair->avp_lvalue == pair_value)
                        return 1;
                check_pairs = pair->next;
        } while (check_pairs
		 && (pair = grad_avl_find(check_pairs, pair_attr)));
        return 0;
}

#ifdef DA_ACCT_TYPE
# define ACCT_TYPE(req,t) check_attribute(req, DA_ACCT_TYPE, t, 1)
#else
# define ACCT_TYPE(req,t) 1
#endif


/*  Store logins in the RADIUS utmp file. */
int
rad_acct_system(radiusd_request_t *radreq, int dowtmp)
{
        struct radutmp  ut;
        grad_avp_t *vp;
        int status = -1;
        int nas_address = 0;
        int protocol = -1;
        time_t t;
        int ret = 0, rc;
        int port_seen = 0;
        char buf[GRAD_MAX_LONGNAME];

	/* Do not do anything if system accounting is not requested */
	if (!acct_system)
		return 0;
	
        /* A packet should have Acct-Status-Type attribute */
        if ((vp = grad_avl_find(radreq->request->avlist, DA_ACCT_STATUS_TYPE))
	        == NULL) {
                grad_log_req(GRAD_LOG_ERR, radreq->request,
                             _("no Acct-Status-Type attribute"));
                return -1;
        }

        status = vp->avp_lvalue;

        time(&t);
        memset(&ut, 0, sizeof(ut));
        ut.porttype = -1; /* Unknown so far */

        if (radreq->realm) {
		grad_server_t *server =
			grad_list_item(radreq->realm->queue->servers,
				       radreq->server_no);
		if (server)
			ut.realm_address = server->addr;
        }
        
        /* Fill in radutmp structure */
        for (vp = radreq->request->avlist; vp; vp = vp->next) {
                switch (vp->attribute) {
                case DA_USER_NAME:
                        backslashify(ut.login, vp->avp_strvalue, RUT_NAMESIZE);
                        break;
			
                case DA_ORIG_USER_NAME:
                        backslashify(ut.orig_login, vp->avp_strvalue, RUT_NAMESIZE);
                        break;
			
                case DA_LOGIN_IP_HOST:
                case DA_FRAMED_IP_ADDRESS:
                        ut.framed_address = htonl(vp->avp_lvalue);
                        break;
			
                case DA_FRAMED_PROTOCOL:
                        protocol = vp->avp_lvalue;
                        break;
			
                case DA_NAS_IP_ADDRESS:
                        nas_address = vp->avp_lvalue;
                        ut.nas_address = htonl(vp->avp_lvalue);
                        break;
			
                case DA_NAS_PORT_ID:
                        ut.nas_port = vp->avp_lvalue;
                        port_seen = 1;
                        break;
			
                case DA_ACCT_DELAY_TIME:
                        ut.delay = vp->avp_lvalue;
                        break;
			
                case DA_CALLING_STATION_ID:
                        store_session_id(ut.caller_id,
                                         sizeof(ut.caller_id),
                                         vp->avp_strvalue,
                                         vp->avp_strlength);
                        break;
			
                case DA_CALLED_STATION_ID:
                        break;
			
                case DA_ACCT_SESSION_ID:
                        store_session_id(ut.session_id,
                                         sizeof(ut.session_id),
                                         vp->avp_strvalue,
                                         vp->avp_strlength);
                        break;
			
                case DA_NAS_PORT_TYPE:
			ut.porttype = vp->avp_lvalue;
                        break;
                }
        }

        if (ut.orig_login[0] == 0) 
                strncpy(ut.orig_login, ut.login, sizeof(ut.orig_login));
        
        /* If we didn't find out the NAS address, use the originator's
           IP address. */
        if (nas_address == 0) {
                nas_address = radreq->request->ipaddr;
                ut.nas_address = htonl(nas_address);
        }

#ifdef LOG_EMPTY_USERNAME 
        if (ut.login[0] == 0 && ut.caller_id[0] != 0) {
                ut.login[0] = '#';
                store_session_id(ut.login+1,
                                 RUT_NAMESIZE-2,
                                 ut.caller_id,
                                 strlen(ut.caller_id));
        }
#endif
        
        ut.proto = protocol;
        ut.time = t - ut.delay;

        /* Process Accounting-On/Off records */
        if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON && nas_address) {
                grad_log(GRAD_LOG_NOTICE, 
                         _("NAS %s started (Accounting-On packet seen)"),
                         grad_nas_ip_to_name(nas_address, buf, sizeof buf));
                radzap(nas_address, -1, NULL, ut.time);
                write_nas_restart(status, ut.nas_address);
                return 0;
        }
        if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF && nas_address) {
                grad_log(GRAD_LOG_NOTICE, 
                         _("NAS %s shut down (Accounting-Off packet seen)"),
                         grad_nas_ip_to_name(nas_address, buf, sizeof buf));
                radzap(nas_address, -1, NULL, ut.time);
                write_nas_restart(status, ut.nas_address);
                return 0;
        }

        /* If we don't know the type of entry pretend we succeeded. */
        if (status != DV_ACCT_STATUS_TYPE_START &&
            status != DV_ACCT_STATUS_TYPE_STOP &&
            status != DV_ACCT_STATUS_TYPE_ALIVE) {
                grad_log_req(GRAD_LOG_NOTICE, 
                             radreq->request, _("unknown packet type (%d)"),
                             status);
                return 0;
        } else if (status == DV_ACCT_STATUS_TYPE_START ||
                   status == DV_ACCT_STATUS_TYPE_STOP) {
                GRAD_DEBUG7(1,
                    "%s: User %s at NAS %s port %d session %-*.*s",
                     status == DV_ACCT_STATUS_TYPE_START ? "start" : "stop",
                     ut.login,
                     grad_nas_ip_to_name(nas_address, buf, sizeof buf),
                     ut.nas_port,
                     sizeof(ut.session_id),
                     sizeof(ut.session_id),
                     ut.session_id);
        }

        /* Decide if we should store this record into radutmp/radwtmp.
           We skip records:

                - if NAS-Port-Id attribute is absent
                - if request has one or more Acct-Type attributes
                  and no one of them requires system accounting.
                  (The Acct-Type pairs can be inserted only via
                   raddb/hints  */
        if (!port_seen)
                return 0;

        if (!ACCT_TYPE(radreq->request->avlist, DV_ACCT_TYPE_SYSTEM)) {
                GRAD_DEBUG1(1,"Acct type system disabled for %s", ut.login);
                return 0;
        }
        
        /* Update radutmp file. */
        rc = grad_utmp_putent(grad_utmp_file, &ut, status);
        GRAD_DEBUG3(1, "grad_utmp_putent=%d for %s/%s",
                    rc, ut.login, ut.session_id);

        /* Don't write wtmp if we don't have a username, or
           if this is an update record and the original record
           was already written. */
        if ((status != DV_ACCT_STATUS_TYPE_STOP && ut.login[0] == 0) ||
            rc == PUTENT_UPDATE)
                dowtmp = 0;

        /* Write a RADIUS wtmp log file. */
        if (dowtmp) {
                stat_update(&ut, status);
                write_wtmp(&ut);
        } else if (rc == PUTENT_UPDATE) {
                stat_update(&ut, status);
        } else {
                ret = -1;
                stat_inc(acct, radreq->request->ipaddr, num_norecords);
                grad_log_req(GRAD_LOG_NOTICE, radreq->request,
			     _("NOT writing wtmp record"));
        }
        return ret;
}

static void
disable_system_acct()
{
        radut_file_t file;
	struct radutmp *up;
	int written = 0;
		
        if ((file = grad_ut_setent(grad_utmp_file, 0)) == NULL)
                return;

        while (up = grad_ut_getent(file)) {
                switch (up->type) {
		case P_LOGIN:
                        up->type = P_IDLE;
                        time(&up->time);
                        grad_ut_putent(file, up);
                        /* Add a logout entry to the wtmp file. */
                        write_wtmp(up);
			break;

		case P_ACCT_ENABLED:
			time(&up->time);
			up->type = P_ACCT_DISABLED;
			grad_ut_putent(file, up);
			write_wtmp(up);
			written = 1;
			break;

		case P_ACCT_DISABLED:
			written = 1;
			break;
                }
	}

	if (!written) {
		struct radutmp ut;
		
		memset(&ut, 0, sizeof ut);
		time(&ut.time);
		ut.type = P_ACCT_DISABLED;
		grad_ut_putent(file, &ut);
	}
	grad_ut_endent(file);
	grad_log(GRAD_LOG_INFO, _("System accounting is disabled"));
}

static void
enable_system_acct()
{
        radut_file_t file;
	struct radutmp *up, ut;
		
        if ((file = grad_ut_setent(grad_utmp_file, 0)) == NULL)
                return;

        while (up = grad_ut_getent(file)) {
                if (up->type == P_ACCT_DISABLED) {
                        up->type = P_ACCT_ENABLED;
                        time(&up->time);
                        grad_ut_putent(file, up);
                        /* Add an entry to the wtmp file. */
                        write_wtmp(up);
                }
	}
	grad_ut_endent(file);
}

void
system_acct_init()
{
	if (acct_system)
		enable_system_acct();
	else
		disable_system_acct();
}

int
mkdir_path(char *path, int perms)
{
	struct stat st;
	
	if (stat(path, &st)) {
		char *p;
		
		if (errno != ENOENT) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
				 _("Cannot stat path component: %s"),
				 path);
			return 1;
		}

		p = strrchr(path, '/');
		if (p && p > path) {
			int rc;
			*p = 0;
			rc = mkdir_path(path, perms);
			*p = '/';
			if (rc)
				return 1;
		}

		if (mkdir(path, perms)) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
				 _("Cannot create directory %s"),
				 path);
			return 1;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		grad_log(GRAD_LOG_ERR,
			 _("Path component is not a directory: %s"),
			 path);
		return 1;
	}
	return 0;
}

static int
check_acct_dir()
{
        struct stat st;

	if (stat(grad_acct_dir, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			if (access(grad_acct_dir, W_OK)) {
				grad_log(GRAD_LOG_ERR,
					 _("%s: directory not writable"),
					 grad_acct_dir);
				return 1;
			}
			return 0;
		} else {
			grad_log(GRAD_LOG_ERR, _("%s: not a directory"),
				 grad_acct_dir);
			return 1;
		}
	}

	if (mkdir_path(grad_acct_dir, 0755)) 
                return 1;
        return 0;
}

static int acct_dir_status;

static void
acct_after_config_hook(void *arg ARG_UNUSED, void *data ARG_UNUSED)
{
	if (auth_detail || acct_detail) {
		acct_dir_status = check_acct_dir();
		if (acct_dir_status) {
			grad_log(GRAD_LOG_NOTICE,
			         _("Detailed accounting is disabled"));
			auth_detail = acct_detail = 0;
		}
	}
}

void
acct_init()
{
	radiusd_set_postconfig_hook(acct_after_config_hook, NULL, 0);
}

static char *
make_legacy_detail_filename(radiusd_request_t *radreq, char *default_filename)
{
	char nasname[GRAD_MAX_LONGNAME];
	grad_nas_t *cl;
	grad_uint32_t ip;
	grad_avp_t *pair;
	
        /* Find out the name of this terminal server. We try to find
           the DA_NAS_IP_ADDRESS in the naslist file. If that fails,
           we look for the originating address.
           Only if that fails we resort to a name lookup. */
	
        cl = NULL;
        ip = radreq->request->ipaddr;
        if ((pair = grad_avl_find(radreq->request->avlist, DA_NAS_IP_ADDRESS)) != NULL)
                ip = pair->avp_lvalue;

        if (radreq->realm) {
		grad_server_t *server =
			grad_list_item(radreq->realm->queue->servers,
				       radreq->server_no);
		if (server)
			ip = server->addr;
	}

        if ((cl = grad_nas_lookup_ip(ip)) != NULL) {
                if (cl->shortname[0])
                        strcpy(nasname, cl->shortname);
                else
                        strcpy(nasname, cl->longname);
        }

        if (cl == NULL) 
                grad_ip_gethostname(ip, nasname, sizeof(nasname));

	return grad_mkfilename(nasname, default_filename);
}

static char *
make_detail_filename(radiusd_request_t *req, char *template,
		     char *default_filename)
{
	if (!template) {
		return make_legacy_detail_filename(req, default_filename);
	} else if (template[0] == '=') {
		grad_value_t val;
		/*FIXME: Should be compiled!*/
		if (rewrite_interpret(template+1, req->request, &val)) 
			return NULL;
		if (val.type != String) {
			grad_log(GRAD_LOG_ERR, "%s: %s",
			         template+1, _("wrong return type"));
			/* Nothing to free in val */
			return NULL;
		}
		return val.datum.sval.data;
	} else {
		struct obstack stk;
		char *ptr;
		
		obstack_init(&stk);
		ptr = radius_xlate(&stk, template, req->request, NULL);
		if (ptr) 
			ptr = grad_estrdup(ptr);
		obstack_free(&stk, NULL);
		return ptr;
	}
}

static int
make_path_to_file(char *filename, int perms)
{
	char *p = strrchr(filename, '/');
	if (p) {
		int rc;
		*p = 0;
		rc = mkdir_path(filename, perms);
		*p = '/';
		return rc;
	}
	return 0;
}

int
write_detail(radiusd_request_t *radreq, int authtype, int rtype)
{
        FILE *outfd;
        char *save;
        grad_avp_t *pair;
        time_t curtime;
        int ret = 0;
	char *filename;
	char *template;
	char *deffilename;
	
	if (acct_dir_status)
		return 1;

	curtime = time(0);

	switch (rtype) {
	case R_ACCT:
		template = acct_detail_template;
		deffilename = "detail";
		break;

	case R_AUTH:
		template = auth_detail_template;
		deffilename = "detail.auth";
		break;

	default:
		return 1;
	}
	
        filename = make_detail_filename(radreq, template, deffilename);
	if (!filename)
		return 1;

	/* Change to the accounting directory */
	if (chdir(grad_acct_dir)) {
		grad_free(filename);
		return 1;
	}
	
        /* Create a directory for this nas. */
        make_path_to_file(filename, 0755);

        /* Write Detail file. */
        if ((outfd = fopen(filename, "a")) == NULL) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open %s"), filename);
                ret = 1;
        } else {

                /* Post a timestamp */
                fprintf(outfd, "%s", ctime(&curtime));

                /* Decide which username to log */
                if (!strip_names) {
                        /* user wants a full (non-stripped) name to appear
                           in detail */
                        
                        pair = grad_avl_find(radreq->request->avlist,
					     DA_ORIG_USER_NAME);
                        if (pair) 
                                pair->name = "User-Name";
                        else
                                pair = grad_avl_find(radreq->request->avlist,
						     DA_USER_NAME);
                        if (pair) {
                                fprintf(outfd, "\t%s\n", 
                                        grad_format_pair(pair, 0, &save));
                                free(save);
                        }
                }

                /* Write each attribute/value to the log file */
                for (pair = radreq->request->avlist; pair; pair = pair->next) {
			if (pair->prop & GRAD_AP_INTERNAL)
				continue;
                        switch (pair->attribute) {
                        case DA_USER_PASSWORD:
                                break;
                        case DA_USER_NAME:
                        case DA_ORIG_USER_NAME:
                                if (!strip_names)
                                        break;
                        default:
                                fprintf(outfd, "\t%s\n", 
                                        grad_format_pair(pair, 0, &save));
                                free(save);
                        } 
                }

                /* Add non-protocol attibutes. */
                fprintf(outfd, "\tTimestamp = %ld\n", curtime);
                switch (authtype) {
		case REQ_AUTH_OK:
			fprintf(outfd, "\tRequest-Authenticator = Verified\n");
                        break;
		case REQ_AUTH_ZERO:
                        fprintf(outfd, "\tRequest-Authenticator = None\n");
                        break;
		case REQ_AUTH_BAD:
                        fprintf(outfd, "\tRequest-Authenticator = Unverified\n");
                        break;
		default:
			fprintf(outfd, "\tRequest-Authenticator = %d\n",
				authtype);
                        break;
                }
                fprintf(outfd, "\n");
                fclose(outfd);
                ret = 0;
        }
	
        grad_free(filename);
        chdir("/");
        return ret;
}

int
rad_acct_db(radiusd_request_t *radreq, int authtype)
{
        int rc = 0;

        if (acct_detail
	    && ACCT_TYPE(radreq->request->avlist, DV_ACCT_TYPE_DETAIL))
                rc = write_detail(radreq, authtype, R_ACCT);
        if (ACCT_TYPE(radreq->request->avlist, DV_ACCT_TYPE_SQL))
                radiusd_sql_acct(radreq);
        return rc;
}

int
rad_acct_ext(radiusd_request_t *radreq)
{
        grad_avp_t *p;
	int rc = 0;
	
#ifdef USE_SERVER_GUILE
        for (p = grad_avl_find(radreq->request->avlist, DA_SCHEME_ACCT_PROCEDURE);
	     p;
	     p = grad_avl_find(p->next, DA_SCHEME_ACCT_PROCEDURE))
                scheme_acct(p->avp_strvalue, radreq);
#endif
        for (p = grad_avl_find(radreq->request->avlist, DA_ACCT_EXT_PROGRAM);
	     p;
	     p = grad_avl_find(p->next, DA_ACCT_EXT_PROGRAM)) {
		radius_eval_avp(radreq, p, NULL, 1);
    		switch (p->avp_strvalue[0]) {
		case '/':
                	rc = radius_exec_program(p->avp_strvalue, radreq, NULL,
						 1);
			break;
		case '|':
                	filter_acct(p->avp_strvalue+1, radreq);
                }
        }
        return rc;
}

/* run accounting modules */
int
rad_accounting(radiusd_request_t *radreq, int activefd, int verified)
{
	log_open(GRAD_LOG_ACCT);

        huntgroup_access(radreq, NULL);

#if defined(RT_ASCEND_EVENT_REQUEST) && defined(RT_ASCEND_EVENT_RESPONSE)
        /* Special handling for Ascend-Event-Request */
        if (radreq->request->code == RT_ASCEND_EVENT_REQUEST) {
                write_detail(radreq, verified, R_ACCT);
                radius_send_reply(RT_ASCEND_EVENT_RESPONSE,
                                  radreq, NULL, NULL, activefd);
                stat_inc(acct, radreq->request->ipaddr, num_resp);
                return 0;
        }
#endif
        
        if (rad_acct_system(radreq, doradwtmp) == 0 &&
            rad_acct_db(radreq, verified) == 0 &&
            rad_acct_ext(radreq) == 0) {
                /* Now send back an ACK to the NAS. */
                radius_send_reply(RT_ACCOUNTING_RESPONSE,
                               radreq, NULL, NULL, activefd);
                stat_inc(acct, radreq->request->ipaddr, num_resp);
                return 0;
        }

        return -1;
}

int
write_nas_restart(int status, grad_uint32_t addr)
{
        struct radutmp ut;

        memset(&ut, 0, sizeof(ut));
        if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON) 
                ut.type = P_NAS_START;
        else
                ut.type = P_NAS_SHUTDOWN;
        ut.nas_address = addr;
        time(&ut.time);
        return write_wtmp(&ut);
}


/* Multiple login checking */

int
radutmp_mlc_collect_user(char *name, radiusd_request_t *request,
			 grad_list_t **sess_list)
{
        radut_file_t file;
	struct radutmp *up;
		
        if ((file = grad_ut_setent(grad_utmp_file, 0)) == NULL)
                return 1;

        while (up = grad_ut_getent(file)) {
                if (strncmp(name, up->login, RUT_NAMESIZE) == 0 &&
                    up->type == P_LOGIN) {
			struct radutmp *tmp;
			
			if (*sess_list == NULL) 
				*sess_list = grad_list_create();
			tmp = grad_emalloc(sizeof(*tmp));
			memcpy(tmp, up, sizeof(*tmp));
			grad_list_append(*sess_list, tmp);
                }
	}
	grad_ut_endent(file);
	return 0;
}

int
radutmp_mlc_collect_realm(radiusd_request_t *request, grad_list_t **sess_list)
{
        radut_file_t file;
	struct radutmp *up;
		
        if ((file = grad_ut_setent(grad_utmp_file, 0)) == NULL)
                return 1;

        while (up = grad_ut_getent(file)) {
                if (up->type == P_LOGIN
		    && grad_realm_verify_ip(request->realm, up->realm_address)) {
			struct radutmp *tmp;
			
			if (*sess_list == NULL) 
				*sess_list = grad_list_create();
			tmp = grad_emalloc(sizeof(*tmp));
			memcpy(tmp, up, sizeof(*tmp));
			grad_list_append(*sess_list, tmp);
                }
	}
	grad_ut_endent(file);
	return 0;
}

void
radutmp_mlc_close(struct radutmp *up)
{
	up->type = P_IDLE;
	up->time = time(NULL);
	grad_utmp_putent(grad_utmp_file, up, DV_ACCT_STATUS_TYPE_STOP);
}

int
radutmp_mlc_enabled_p()
{
	return acct_system;
}
	









