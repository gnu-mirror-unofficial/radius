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

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <signal.h>

#include <radiusd.h>
#include <radutmp.h>
#define CNTL_STATE_DECL
#include <radctl.h>

/*
 * Format of the control requests:
 *     User-Name     = <valid user name>
 *     Password      = <valid password>
 *     State         = <command>
 *     Class         = <argument to the command>
 * Format of the replies:
 *     code          = PW_AUTHENTICATION_ACK | PW_AUTHENTICATION_REJECT
 *     Reply-Message = <textual information>
 */


static char *what_str[] = {
	"config",
	"all configuration files",
	"dictionaries",
	"users",
	"huntgroups",
	"hints",
	"clients",
	"naslist",
	"realms",
	"deny list",
#ifdef USE_SQL
	"SQL"
#endif	
};


struct keyword cntl_reload[] = {
	"config", reload_config,
	"all", reload_all,
	"dict", reload_dict,
	"users", reload_users,
	"huntgroups", reload_huntgroups,
	"hints", reload_hints,
	"clients", reload_clients,
	"naslist", reload_naslist,
	"realms", reload_realms,
	"deny", reload_deny,
#ifdef USE_SQL	
	"sql", reload_sql,
#endif
	0
};

static char  reply_msg[4096];
static char  *reply_ptr;

int
format_reply(s)
	char *s;
{
	int length = strlen(s);

	if (reply_ptr + length + 3 >= reply_msg + sizeof(reply_msg)) {
		radlog(L_NOTICE,
		       _("reply message overflow while answering control request"));
		return 0;
	}
	strcpy(reply_ptr, s);
	reply_ptr += length;
	*reply_ptr++ = '\r';
	*reply_ptr++ = '\n';
	*reply_ptr = 0;
}

int
cntl_respond(fd, sa, salen, buf, size)
	int fd;
	struct sockaddr *sa;
	int salen;
	char *buf;
	int size;
{
	AUTH_REQ           *authreq;
	VALUE_PAIR         *pair, *namepair;
	char	   	   pw_digest[AUTH_PASS_LEN];
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	int                reply_code = PW_AUTHENTICATION_REJECT;
	int                code, rc;
	VALUE_PAIR         *user_check, *user_reply;
	char               userpass[AUTH_STRING_LEN];
	char               tbuf[512];
	extern char **xargv;	

	authreq = radrecv(ntohl(sin->sin_addr.s_addr),
			  ntohs(sin->sin_port),
			  buf,
			  size);

        /* Authorize request
	 */

	namepair = pairfind(authreq->request, DA_USER_NAME);
	if (!namepair) {
		radlog(L_NOTICE,
		       _("control channel: no username in request"));
		authfree(authreq);
		return -1;
	}
	
	calc_digest(pw_digest, authreq);

	pairdelete(&authreq->request, DA_NAS_IP_ADDRESS);
	pair = create_pair(DA_NAS_IP_ADDRESS, 0, NULL, authreq->ipaddr);
	pairadd(&authreq->request, pair);
	
	user_check = user_reply = NULL;
	if (user_find(namepair->strvalue, authreq->request,
		      &user_check, &user_reply) != 0) {
		radlog(L_NOTICE, _("Invalid user: [%s] (from %s) trying to access control channel"),
		       namepair->strvalue,
		       nas_name2(authreq));
		rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
			       NULL, _("Access denied"), fd);
		authfree(authreq);
		return -1;
	}

	userpass[0] = 0;
	rc = rad_check_password(authreq, fd, user_check,
				namepair, pw_digest,
				&reply_ptr, userpass);
	if (rc) {
		rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
			       user_reply, reply_ptr, fd);
		if (log_mode & RLOG_FAILED_PASS) {
			radlog(L_NOTICE,
			       _("control channel: Login incorrect: [%s/%s] (from %s)"),
			       namepair->strvalue,
			       userpass,
			       nas_name2(authreq));
		} else {			
			radlog(L_AUTH,
			       _("control channel: Login incorrect: [%s] (from %s)"),
			       namepair->strvalue,
			       nas_name2(authreq));
		}
		pairfree(user_check);
		pairfree(user_reply);
		authfree(authreq);
		return -1;
	}
	
        /* OK. Now let's process it
	 */
	
	pair = pairfind(authreq->request, DA_STATE);
	if (!pair) {
		radlog(L_ERR,
		       _("no State attribute in control packet"));
		pairfree(user_check);
		pairfree(user_reply);
		authfree(authreq);
		return -1;
	}

	reply_msg[0] = 0;
	switch (xlat_keyword(cntl_state, pair->strvalue, -1)) {
	case CNTL_GETPID:
		sprintf(reply_msg, _("RADIUS pid %ld"), radius_pid);
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_GETMSTAT:
		reply_ptr = reply_msg;
		format_reply(_("Memory usage:"));
		meminfo(format_reply);
#ifdef LEAK_DETECTOR
		sprintf(tbuf, _("malloc statistics: %d blocks, %d bytes"),
			mallocstat.count, mallocstat.size);
		format_reply(tbuf);
#endif
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_GETQSTAT:
		reply_ptr = reply_msg;
		format_reply(_("Request queue statistics:"));
		stat_request_list(format_reply);
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_GETUSER: 
		if ((pair = pairfind(authreq->request, DA_CLASS)) == NULL) {
			sprintf(reply_msg, _("no user specified"));
			radlog(L_WARN, _("no user specified in GETUSER control packet"));
			break;
		}
		sprintf(reply_msg, _("CNTL_GETUSER: not implemented"));
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_DUMPDB:
		radlog(L_INFO, _("Dumping users db to `%s'"),
		       RADIUS_DUMPDB_NAME);
		dump_users_db();
		sprintf(reply_msg, _("Database dumped into `%s'"),
			RADIUS_DUMPDB_NAME);
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_RELOAD:
		if ((pair = pairfind(authreq->request, DA_CLASS)) == NULL)
			code = reload_all;
		else 
			code = xlat_keyword(cntl_reload, pair->strvalue, -1);

		switch (code) {
		case reload_all:
		case reload_dict:
		case reload_users:
		case reload_huntgroups:
		case reload_hints:
		case reload_clients:
		case reload_naslist:
		case reload_realms:
		case reload_deny:
#ifdef USE_SQL				
		case reload_sql:
#endif
			rc = reload_config_file(code);
			sprintf(reply_msg, _("Reloading %s: %d"),
				what_str[code], rc);
			reply_code = PW_AUTHENTICATION_ACK;
			break;

		case reload_config:
			rc = get_config();
			sprintf(reply_msg, _("Reloading %s: %d"),
				what_str[code], rc);
			reply_code = PW_AUTHENTICATION_ACK;
			break;
			
		default:
			sprintf(reply_msg, _("Unknown configuration file: %s"),
				pair->strvalue);
			reply_code = PW_AUTHENTICATION_REJECT;
		}
		break;
		
	case CNTL_RESTART:
		if (xargv[0][0] != '/') {
			reply_code = PW_AUTHENTICATION_REJECT;
			sprintf(reply_msg, _("can't restart: RADIUSD not started as absolute pathname"));
			break;
		}
		reply_code = PW_AUTHENTICATION_ACK;
		sprintf(reply_msg, _("restart initiated"));
		rad_send_reply(reply_code, authreq,
			       NULL, reply_msg, fd);
		pairfree(user_check);
		pairfree(user_reply);
		authfree(authreq);
		rad_restart();
		break;
		
	case CNTL_SHUTDOWN:
		reply_code = PW_AUTHENTICATION_ACK;
		radlog(L_NOTICE,
		       _("control channel: shutdown initiated"));
		sprintf(reply_msg, _("shutdown initiated"));
		rad_send_reply(reply_code, authreq,
			       NULL, reply_msg, fd);
		pairfree(user_check);
		pairfree(user_reply);
		authfree(authreq);
		rad_exit(SIGTERM);
		break;

	case CNTL_SUSPEND:
		sprintf(reply_msg, _("CNTL_SUSPEND not implemented"));
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	case CNTL_CONTINUE:
		sprintf(reply_msg, _("CNTL_CONTINUE not implemented"));
		reply_code = PW_AUTHENTICATION_ACK;
		break;
		
	default:
		radlog(L_ERR,
		       _("unknown command `%s' in control packet"),
		       pair->strvalue);
		sprintf(reply_msg, _("unknown command: %s"),
			pair->strvalue);
	}

	rad_send_reply(reply_code, authreq,
		       NULL, reply_msg[0] ? reply_msg : NULL, fd);

	pairfree(user_check);
	pairfree(user_reply);
	authfree(authreq);
	return 0;
}



