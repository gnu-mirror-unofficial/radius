/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

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

#define RADIUS_MODULE_ACCT_C 

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
#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#ifdef USE_SQL
# include <radsql.h>
#endif

int     doradwtmp = 1;

static int write_wtmp(struct radutmp *ut);
static int write_nas_restart(int status, UINT4 addr);
static int check_ts(struct radutmp *ut);

int rad_acct_system(RADIUS_REQ *radreq, int dowtmp);
int rad_acct_db(RADIUS_REQ *radreq, int authtype);
int rad_acct_ext(RADIUS_REQ *radreq);


/* Zap a user, or all users on a NAS, from the radutmp file. */
int
radzap(UINT4 nasaddr, int port, char *user, time_t t)
{
        struct radutmp  *up;
        radut_file_t    file;
        UINT4           netaddr;
        
        if (t == 0) time(&t);
        netaddr = htonl(nasaddr);

        if (file = rut_setent(radutmp_path, 0)) {
                /* Find the entry for this NAS / portno combination. */
                while (up = rut_getent(file)) {
                        if (((nasaddr != 0 && netaddr != up->nas_address) ||
                             (port >= 0   && port    != up->nas_port) ||
                             (user != NULL && strcmp(up->login, user) != 0) ||
                             up->type != P_LOGIN))
                                continue;
                        /* Zap the entry */
                        up->type = P_IDLE;
                        up->time = t;
                        rut_putent(file, up);
                        /* Add a logout entry to the wtmp file. */
                        write_wtmp(up);
                }
                rut_endent(file);
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
        return radwtmp_putent(radwtmp_path, ut);
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
check_attribute(VALUE_PAIR *check_pairs, int pair_attr,
		int pair_value, int def)
{
        VALUE_PAIR *pair;

        if ((pair = avl_find(check_pairs, pair_attr)) == NULL)
                return def;
        do {
                if (pair->avp_lvalue == pair_value)
                        return 1;
                check_pairs = pair->next;
        } while (check_pairs && (pair = avl_find(check_pairs, pair_attr)));
        return 0;
}

#ifdef DA_ACCT_TYPE
# define ACCT_TYPE(req,t) check_attribute(req, DA_ACCT_TYPE, t, 1)
#else
# define ACCT_TYPE(req,t) 1
#endif


/*  Store logins in the RADIUS utmp file. */
int
rad_acct_system(RADIUS_REQ *radreq, int dowtmp)
{
        struct radutmp  ut;
        VALUE_PAIR *vp;
        int status = -1;
        int nas_address = 0;
        int protocol = -1;
        time_t t;
        int ret = 0, rc;
        int port_seen = 0;
        char buf[MAX_LONGNAME];

        /* A packet should have Acct-Status-Type attribute */
        if ((vp = avl_find(radreq->request, DA_ACCT_STATUS_TYPE)) == NULL) {
                radlog_req(L_ERR, radreq,
                           _("no Acct-Status-Type attribute"));
                return -1;
        }

        status = vp->avp_lvalue;

        time(&t);
        memset(&ut, 0, sizeof(ut));
        ut.porttype = -1; /* Unknown so far */

        if (radreq->realm) {
		RADIUS_SERVER *server = list_item(radreq->realm->queue->servers,
						  radreq->server_no);
		if (server)
			ut.realm_address = server->addr;
        }
        
        /* Fill in radutmp structure */
        for (vp = radreq->request; vp; vp = vp->next) {
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
                nas_address = radreq->ipaddr;
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
                radlog(L_NOTICE, 
                        _("NAS %s started (Accounting-On packet seen)"),
                        nas_ip_to_name(nas_address, buf, sizeof buf));
                radzap(nas_address, -1, NULL, ut.time);
                write_nas_restart(status, ut.nas_address);
                return 0;
        }
        if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF && nas_address) {
                radlog(L_NOTICE, 
                        _("NAS %s shut down (Accounting-Off packet seen)"),
                        nas_ip_to_name(nas_address, buf, sizeof buf));
                radzap(nas_address, -1, NULL, ut.time);
                write_nas_restart(status, ut.nas_address);
                return 0;
        }

        /* If we don't know the type of entry pretend we succeeded. */
        if (status != DV_ACCT_STATUS_TYPE_START &&
            status != DV_ACCT_STATUS_TYPE_STOP &&
            status != DV_ACCT_STATUS_TYPE_ALIVE) {
                radlog_req(L_NOTICE, 
                           radreq, _("unknown packet type (%d)"),
                           status);
                return 0;
        } else if (status == DV_ACCT_STATUS_TYPE_START ||
                   status == DV_ACCT_STATUS_TYPE_STOP) {
                debug(1,
                    ("%s: User %s at NAS %s port %d session %-*.*s",
                     status == DV_ACCT_STATUS_TYPE_START ? "start" : "stop",
                     ut.login,
                     nas_ip_to_name(nas_address, buf, sizeof buf),
                     ut.nas_port,
                     sizeof(ut.session_id),
                     sizeof(ut.session_id),
                     ut.session_id));
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

        if (!ACCT_TYPE(radreq->request, DV_ACCT_TYPE_SYSTEM)) {
                debug(1,("Acct type system disabled for %s", ut.login));
                return 0;
        }
        
        /* Update radutmp file. */
        rc = radutmp_putent(radutmp_path, &ut, status);
        debug(1, ("radutmp_putent=%d for %s/%s",
                  rc,
                  ut.login,
                  ut.session_id));

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
                stat_inc(acct, radreq->ipaddr, num_norecords);
                radlog_req(L_NOTICE, radreq, _("NOT writing wtmp record"));
        }
        return ret;
}

static int
check_acct_dir()
{
        struct stat st;

        if (stat(radacct_dir, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
			if (access(radacct_dir, W_OK)) {
				radlog(L_ERR,
				       _("%s: directory not writable"),
				       radacct_dir);
				return 1;
			}
                        return 0;
		} else {
                        radlog(L_ERR, _("%s: not a directory"),
			       radacct_dir);
                        return 1;
                }
        }
        if (mkdir(radacct_dir, 0755)) {
                radlog(L_ERR|L_PERROR,
                        _("can't create accounting directory `%s'"),
                        radacct_dir);
                return 1;
        }
        return 0;
}

static int acct_dir_status;

static void
acct_after_config_hook(void *arg ARG_UNUSED, void *data ARG_UNUSED)
{
	if (auth_detail || acct_detail) {
		acct_dir_status = check_acct_dir();
		if (acct_dir_status) {
			radlog(L_NOTICE,
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

int
write_detail(RADIUS_REQ *radreq, int authtype, char *f)
{
        FILE *outfd;
        char nasname[MAX_LONGNAME];
        char *dir, *path;
        char *save;
        VALUE_PAIR *pair;
        UINT4 nas;
        NAS *cl;
        time_t curtime;
        int ret = 0;

	if (acct_dir_status)
		return;
	
        curtime = time(0);
        
        /* Find out the name of this terminal server. We try to find
           the DA_NAS_IP_ADDRESS in the naslist file. If that fails,
           we look for the originating address.
           Only if that fails we resort to a name lookup. */
        cl = NULL;
        nas = radreq->ipaddr;
        if ((pair = avl_find(radreq->request, DA_NAS_IP_ADDRESS)) != NULL)
                nas = pair->avp_lvalue;
        if (radreq->realm) {
		RADIUS_SERVER *server = list_item(radreq->realm->queue->servers,
						  radreq->server_no);
		if (server)
			nas = server->addr;
	}

        if ((cl = nas_lookup_ip(nas)) != NULL) {
                if (cl->shortname[0])
                        strcpy(nasname, cl->shortname);
                else
                        strcpy(nasname, cl->longname);
        }

        if (cl == NULL) 
                ip_gethostname(nas, nasname, sizeof(nasname));
        
        /* Create a directory for this nas. */
        dir = mkfilename(radacct_dir, nasname);
        mkdir(dir, 0755);

        /* Write Detail file. */
        path = mkfilename(dir, f);
        efree(dir);
        if ((outfd = fopen(path, "a")) == (FILE *)NULL) {
                radlog(L_ERR|L_PERROR, _("can't open %s"), path);
                ret = -1;
        } else {

                /* Post a timestamp */
                fprintf(outfd, "%s", ctime(&curtime));

                /* Decide which username to log */
                if (!strip_names) {
                        /* user wants a full (non-stripped) name to appear
                           in detail */
                        
                        pair = avl_find(radreq->request, DA_ORIG_USER_NAME);
                        if (pair) 
                                pair->name = "User-Name";
                        else
                                pair = avl_find(radreq->request, DA_USER_NAME);
                        if (pair) {
                                fprintf(outfd, "\t%s\n", 
                                        format_pair(pair, 0, &save));
                                free(save);
                        }
                }

                /* Write each attribute/value to the log file */
                for (pair = radreq->request; pair; pair = pair->next) {
			if (pair->prop & AP_INTERNAL)
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
                                        format_pair(pair, 0, &save));
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
        efree(path);
        
        return ret;
}

int
rad_acct_db(RADIUS_REQ *radreq, int authtype)
{
        int rc = 0;

        if (acct_detail && ACCT_TYPE(radreq->request, DV_ACCT_TYPE_DETAIL))
                rc = write_detail(radreq, authtype, "detail");
#ifdef USE_SQL
        if (ACCT_TYPE(radreq->request, DV_ACCT_TYPE_SQL))
                rad_sql_acct(radreq);
#endif
        return rc;
}

int
rad_acct_ext(RADIUS_REQ *radreq)
{
        VALUE_PAIR *p;

#ifdef USE_SERVER_GUILE
        for (p = avl_find(radreq->request, DA_SCHEME_ACCT_PROCEDURE);
	     p;
	     p = avl_find(p->next, DA_SCHEME_ACCT_PROCEDURE))
                scheme_acct(p->avp_strvalue, radreq);
#endif
        for (p = avl_find(radreq->request, DA_ACCT_EXT_PROGRAM);
	     p;
	     p = avl_find(p->next, DA_ACCT_EXT_PROGRAM)) {
    		switch (p->avp_strvalue[0]) {
		case '/':
                	radius_exec_program(p->avp_strvalue, radreq, NULL, 0);
			break;
		case '|':
                	filter_acct(p->avp_strvalue+1, radreq);
                }
        }
        return 0;
}

/* run accounting modules */
int
rad_accounting(RADIUS_REQ *radreq, int activefd, int verified)
{
	log_open(L_ACCT);

        huntgroup_access(radreq, NULL);

#if defined(RT_ASCEND_EVENT_REQUEST) && defined(RT_ASCEND_EVENT_RESPONSE)
        /* Special handling for Ascend-Event-Request */
        if (radreq->code == RT_ASCEND_EVENT_REQUEST) {
                write_detail(radreq, verified, "detail");
                radius_send_reply(RT_ASCEND_EVENT_RESPONSE,
                                  radreq, NULL, NULL, activefd);
                stat_inc(acct, radreq->ipaddr, num_resp);
                return 0;
        }
#endif
        
        if (rad_acct_system(radreq, doradwtmp) == 0 &&
            rad_acct_db(radreq, verified) == 0 &&
            rad_acct_ext(radreq) == 0) {
                /* Now send back an ACK to the NAS. */
                radius_send_reply(RT_ACCOUNTING_RESPONSE,
                               radreq, NULL, NULL, activefd);
                stat_inc(acct, radreq->ipaddr, num_resp);
                return 0;
        }

        return -1;
}

/* Check one terminal server to see if a user is logged in.
   Return value:
        1 if user is logged in
        0 if user is not logged in */

static int
rad_check_ts(struct radutmp *ut)
{
        int result;
        
        switch (result = check_ts(ut)) {
        case 0:
        case 1:
                return result;

                /* The default return value is a question of policy.
                   It is defined in /etc/raddb/config */
        default:
                if (checkrad_assume_logged) 
                        radlog(L_NOTICE, _("assuming `%s' is logged in"),
                               ut->login);
                else
                        radlog(L_NOTICE, _("assuming `%s' is NOT logged in"),
                               ut->login);
                return checkrad_assume_logged;
        }
        /*NOTREACHED*/
}

/* Return value: that of CHECKRAD process, i.e. 1 means true (user FOUND)
   0 means false (user NOT found) */
static int
check_ts(struct radutmp *ut)
{
        NAS     *nas;

        /* Find NAS type. */
        if ((nas = nas_lookup_ip(ntohl(ut->nas_address))) == NULL) {
                radlog(L_NOTICE, _("check_ts(): unknown NAS"));
                return -1; 
        }

        /* Handle two special types */
        if (strcmp(nas->nastype, "true") == 0)
                return 1;
        else if (strcmp(nas->nastype, "false") == 0)
                return 0;

        return checkrad(nas, ut);
}

int
rad_check_realm(REALM *realm)
{
        int count;
        struct radutmp *up;
        radut_file_t file;
        size_t maxlogins;
		
        if (!realm || (maxlogins = realm_get_quota(realm)) == 0)
                return 0;

        if ((file = rut_setent(radutmp_path, 0)) == NULL)
                return 0;

        /* Pass I: scan radutmp file */
        count = 0;
        while (up = rut_getent(file))
                if (up->type == P_LOGIN
		    && realm_verify_ip(realm, up->realm_address))
                        count++;

        if (count < maxlogins) {
                rut_endent(file);
                return 0;
        }

        /* Pass II: verify logins */
        rut_rewind(file);
        count = 0;

        while (up = rut_getent(file)) {
                if (!(up->type == P_LOGIN
		      && realm_verify_ip(realm, up->realm_address)))
                        continue;

                if (rad_check_ts(up) == 1) {
                        count++;
                } else {
                        /* Hung record - zap it. */
                        up->type = P_IDLE;
                        up->time = time(NULL);
                                
                        rut_putent(file, up);
                        write_wtmp(up);
                }
        }
        rut_endent(file);
        return !(count < maxlogins);
}

/* See if a user is already logged in.
   Check twice. If on the first pass the user exceeds his
   max. number of logins, do a second pass and validate all
   logins by querying the terminal server.

   MPP validation is not as reliable as I'd wish it to be.

   Return:
      0 == OK,
      1 == user exceeds its simultaneous-use parameter */
int
rad_check_multi(char *name, VALUE_PAIR *request, int maxsimul, int *pcount)
{
        radut_file_t file;
        int             count;
        struct radutmp  *up;
        VALUE_PAIR      *fra;
        int             mpp = 1; /* MPP flag. The sense is reversed: 1 if
                                    the session is NOT an MPP one */
        UINT4           ipno = 0;
        
        if ((file = rut_setent(radutmp_path, 0)) == NULL)
                return 0;

        /*
         * Pass I.
         */
        count = 0;
        while (up = rut_getent(file)) 
                if (strncmp(name, up->login, RUT_NAMESIZE) == 0 &&
                    up->type == P_LOGIN) {
                        count++;
                }

        *pcount = count;
        
        if (count < maxsimul) {
                rut_endent(file);
                return 0;
        }


        if ((fra = avl_find(request, DA_FRAMED_IP_ADDRESS)) != NULL)
                ipno = htonl(fra->avp_lvalue);

        /* Pass II. Check all registered logins. */

        count = 0;

        rut_rewind(file);
        while (up = rut_getent(file)) {
                if (strncmp(name, up->login, RUT_NAMESIZE) == 0
                    && up->type == P_LOGIN) {
                        if (rad_check_ts(up) == 1) {
                                count++;
                                /* Does it look like a MPP attempt? */
                                if (ipno && up->framed_address == ipno)
                                        switch (up->proto) {
                                        case DV_FRAMED_PROTOCOL_PPP:
                                        case DV_FRAMED_PROTOCOL_SLIP:
                                        case 256: /* Ascend MPP */
                                        	mpp = 0;
                                        }
                        } else {
                                /* Hung record */
                                up->type = P_IDLE;
                                up->time = time(NULL);
                                rut_putent(file, up);
                                write_wtmp(up);
                        }
                }
        }
        rut_endent(file);

        *pcount = count;
        return (count < maxsimul) ? 0 : mpp;
}

int
write_nas_restart(int status, UINT4 addr)
{
        struct radutmp ut;

        bzero(&ut, sizeof(ut));
        if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON) 
                ut.type = P_NAS_START;
        else
                ut.type = P_NAS_SHUTDOWN;
        ut.nas_address = addr;
        time(&ut.time);
        return write_wtmp(&ut);
}











