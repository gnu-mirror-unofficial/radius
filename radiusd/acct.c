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
#define RADIUS_MODULE 3

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif
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
#ifdef sun
# include <fcntl.h>
#endif
#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#ifdef USE_SQL
# include <radsql.h>
#endif

/*
 *	FIXME: this should be configurable.
 */
int	doradwtmp = 1;

static char porttypes[] = "ASITX";
static int write_wtmp(struct radutmp *ut, int status);
static int write_nas_restart(int status, UINT4 addr);
static int check_ts(struct radutmp *ut);


/*
 *	Zap a user, or all users on a NAS, from the radutmp file.
 */
int
radzap(nasaddr, port, user, t)
	UINT4 nasaddr;
	int port;
	char *user;
	time_t t;
{
	struct radutmp	u;
	int		fd;
	UINT4		netaddr;
	
	if (t == 0) time(&t);
	netaddr = htonl(nasaddr);

	if ((fd = open(radutmp_path, O_RDWR|O_CREAT, 0644)) >= 0) {

	 	/*
		 *	Find the entry for this NAS / portno combination.
		 */

		while (read(fd, &u, sizeof(u)) == sizeof(u)) {
			if (((nasaddr != 0 && netaddr != u.nas_address) ||
			     (port >= 0   && port    != u.nas_port) ||
			     (user != NULL && strcmp(u.login, user) != 0) ||
			     u.type != P_LOGIN))
				continue;
			/*
			 *	Match. Zap it.
			 */
			
			if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
				radlog(L_ERR|L_PERROR, 
				       _("radzap(): negative lseek"));
				lseek(fd, (off_t)0, SEEK_SET);
			}
			/* Lock the utmp file.  */
			rad_lock(fd, sizeof(u), 0, SEEK_CUR);
			
			u.type = P_IDLE;
			u.time = t;
			write(fd, &u, sizeof(u));
			
			/* Unlock the file */
			rad_unlock(fd, sizeof(u), -(off_t)sizeof(u), SEEK_CUR);
			
			/*
			 *	Add a logout entry to the wtmp file.
			 */
			write_wtmp(&u, DV_ACCT_STATUS_TYPE_STOP);
		}
		close(fd);
	}

	return 0;
}

static void
store_session_id(buffer, len, id, idlen)
	char *buffer;
	int len;
	char *id;
	int idlen;
{
	int off = idlen - len;
	if (off < 0)
		off = 0;
	memcpy(buffer, id + off, len);
	buffer[len-1] = 0;
}


void
clear_record(fd, up)
	int fd;
	struct radutmp *up;
{
	bzero(up, sizeof(*up));
	if (lseek(fd, -(off_t)sizeof(*up), SEEK_CUR) < 0) {
		radlog(L_ERR|L_PERROR, _("clear_record(): negative lseek"));
		lseek(fd, (off_t)0, SEEK_SET);
	}
	write(fd, up, sizeof(*up));
}

void
decode_phone_number(buf, size, nstr)
	char *buf;
	int size;
	char *nstr;
{
	int len;

	if (*nstr == '?') {
		buf[0] = '?';
		buf[1] = 0;
	} else {
		if (!isdigit(*nstr))
			nstr++;
		nstr++;
		len = strlen(nstr);
		if (len <= 1) {
			buf[0] = '?';
			buf[1] = 0;
		} else {
			if (len > size)
				len = size;
			strncpy(buf, nstr, len-1);
			buf[len-1] = 0;
		}
	}
}



int
write_wtmp(ut, status)
	struct radutmp *ut;
	int status;
{
	FILE *fp;
		
	fp = fopen(radwtmp_path, "a");
	if (fp == NULL) {
		radlog(L_ERR|L_PERROR, _("can't open %s"), RADWTMP);
		return 1;
	}
	fwrite(ut, sizeof(*ut), 1, fp);
	fclose(fp);
	return 0;
}

void
backslash(dst, src, len)
	char *dst;
	char *src;
	int len;
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

#if 0
/* FIXME: still not needed */
   
int
check_attribute(check_pairs, pair_attr, pair_value, def)
	VALUE_PAIR *check_pairs;
	int pair_attr;
	int pair_value;
	int def;
{
	VALUE_PAIR *pair;

	pair = check_pairs;
	while (check_pairs && pair = pairfind(check_pairs, pair_attr)) {
		if (pair->lvalue == pair_value)
			return 1;
		check_pairs = pair->next;
	}
	return def;
}
#endif

/*
 *	Store logins in the RADIUS utmp file.
 */
int
rad_accounting_new(authreq, dowtmp)
	AUTH_REQ *authreq;
	int dowtmp;
{
	struct radutmp	ut, u;
	VALUE_PAIR	*vp;
	int		rb_record = 0;
	int		status = -1;
	int		nas_address = 0;
	int		framed_address = 0;
	int		protocol = -1;
	time_t		t;
	int		fd;
	int		ret = 0;
	int		just_an_update = 0;
	int		port_seen = 0;
	int		nas_port_type = 0;
	char           *called_id = NULL;
	
	/*
	 *	Which type is this.
	 */
	if ((vp = pairfind(authreq->request, DA_ACCT_STATUS_TYPE)) == NULL) {
		radlog(L_ERR, _("no Acct-Status-Type record (from nas %s)"),
			nas_name2(authreq));
		return -1;
	}
	status = vp->lvalue;
	if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON ||
	    status == DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF)
		rb_record = 1;

	if (!rb_record &&
	    (vp = pairfind(authreq->request, DA_USER_NAME)) == NULL) do {
		int check1 = 0;
		int check2 = 0;

		/*
		 *	ComOS (up to and including 3.5.1b20) does not send
		 *	standard DV_ACCT_STATUS_TYPE_ACCOUNTING_XXX messages.
		 *
		 *	Check for:  o no Acct-Session-Time, or time of 0
		 *		    o Acct-Session-Id of "00000000".
		 *
		 *	We could also check for NAS-Port, that attribute
		 *	should NOT be present (but we don't right now).
	 	 */
		if ((vp = pairfind(authreq->request, DA_ACCT_SESSION_TIME))
		     == NULL || vp->lvalue == 0)
			check1 = 1;
		if ((vp = pairfind(authreq->request, DA_ACCT_SESSION_ID))
		     != NULL && vp->strlength == 8 &&
		     memcmp(vp->strvalue, "00000000", 8) == 0)
			check2 = 1;
		if (check1 == 0 || check2 == 0) {
#if 0 /* Cisco sometimes sends START records without username. */
			radlog(L_ERR, _("no username in record"));
			return -1;
#else
			break;
#endif
		}
		radlog(L_INFO, _("converting reboot records"));
		if (status == DV_ACCT_STATUS_TYPE_STOP)
			status = DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF;
		if (status == DV_ACCT_STATUS_TYPE_START)
			status = DV_ACCT_STATUS_TYPE_ACCOUNTING_ON;
		rb_record = 1;
	} while (0);  /* hack to make break in the above code work */

#ifdef NT_DOMAIN_HACK
        if (!rb_record && vp) {
		char buffer[AUTH_STRING_LEN];
		char *ptr;
		if ((ptr = strchr(vp->strvalue, '\\')) != NULL) {
			strncpy(buffer, ptr + 1, sizeof(buffer));
			buffer[sizeof(buffer) - 1] = 0;
			strcpy(vp->strvalue, buffer);
		}
	}
#endif

	/*
	 *	Add any specific attributes for this username.
	 */
	if (!rb_record && vp != NULL) {
		hints_setup(authreq->request);
		presuf_setup(authreq->request);
	}
	time(&t);
	memset(&ut, 0, sizeof(ut));
	ut.porttype = 'A';

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = authreq->request; vp; vp = vp->next) {
		switch (vp->attribute) {
		case DA_USER_NAME:
			backslash(ut.login, vp->strvalue, RUT_NAMESIZE);
			break;
		case DA_ORIG_USER_NAME:
			backslash(ut.orig_login, vp->strvalue, RUT_NAMESIZE);
			break;
		case DA_LOGIN_IP_HOST:
		case DA_FRAMED_IP_ADDRESS:
			framed_address = vp->lvalue;
			ut.framed_address = htonl(vp->lvalue);
			break;
		case DA_FRAMED_PROTOCOL:
			protocol = vp->lvalue;
			break;
		case DA_NAS_IP_ADDRESS:
			nas_address = vp->lvalue;
			ut.nas_address = htonl(vp->lvalue);
			break;
		case DA_NAS_PORT_ID:
			ut.nas_port = vp->lvalue;
			port_seen = 1;
			break;
		case DA_ACCT_DELAY_TIME:
			ut.delay = vp->lvalue;
			break;
		case DA_CALLING_STATION_ID:
			store_session_id(ut.caller_id,
					 sizeof(ut.caller_id),
					 vp->strvalue,
					 vp->strlength);
			break;
		case DA_CALLED_STATION_ID:
			called_id = vp->strvalue;
			break;
		case DA_ACCT_SESSION_ID:
			store_session_id(ut.session_id,
					 sizeof(ut.session_id),
					 vp->strvalue,
					 vp->strlength);
			break;
		case DA_NAS_PORT_TYPE:
			if (vp->lvalue >= 0 && vp->lvalue <= 4)
				ut.porttype = porttypes[vp->lvalue];
			nas_port_type = vp->lvalue;
			break;
		}
	}

	if (ut.orig_login[0] == 0) 
		strncpy(ut.orig_login, ut.login, sizeof(ut.orig_login));
	
	/*
	 *	If we didn't find out the NAS address, use the
	 *	originator's IP address.
	 */
	if (nas_address == 0) {
		nas_address = authreq->ipaddr;
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
	
	if (protocol == DV_FRAMED_PROTOCOL_PPP)
		ut.proto = 'P';
	else if (protocol == DV_FRAMED_PROTOCOL_SLIP)
		ut.proto = 'S';
	else
		ut.proto = 'T';
	ut.time = t - ut.delay;

	/*
	 *	See if this was a portmaster reboot.
	 */
	if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON && nas_address) {
		radlog(L_INFO, _("NAS %s restarted (Accounting-On packet seen)"),
			nas_name(nas_address));
		radzap(nas_address, -1, NULL, ut.time);
		write_nas_restart(status, ut.nas_address);
		return 0;
	}
	if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_OFF && nas_address) {
		radlog(L_INFO, _("NAS %s rebooted (Accounting-Off packet seen)"),
			nas_name(nas_address));
		radzap(nas_address, -1, NULL, ut.time);
		write_nas_restart(status, ut.nas_address);
		return 0;
	}

	/*
	 *	If we don't know this type of entry pretend we succeeded.
	 */
	if (status != DV_ACCT_STATUS_TYPE_START &&
	    status != DV_ACCT_STATUS_TYPE_STOP &&
	    status != DV_ACCT_STATUS_TYPE_ALIVE) {
		radlog(L_NOTICE, _("NAS %s port %d unknown packet type (%d)"),
			nas_name(nas_address), ut.nas_port, status);
		return 0;
	} else if (status == DV_ACCT_STATUS_TYPE_START ||
		   status == DV_ACCT_STATUS_TYPE_STOP) {
		debug(1,
		    ("%s: User %s at NAS %s port %d session %-*.*s",
		     status == DV_ACCT_STATUS_TYPE_START ? "start" : "stop",
		     ut.login,
		     nas_name(nas_address),
		     ut.nas_port,
		     sizeof(ut.session_id),
		     sizeof(ut.session_id),
		     ut.session_id));
	}

#ifdef USE_NOTIFY
	if (!port_seen) {
		notify_acct(ut.login, status, called_id);
	}
#endif
	
        /*
	 *	Perhaps we don't want to store this record into
	 *	radutmp/radwtmp. We skip records:
	 *
	 *	- without a NAS-Port-Id (telnet / tcp access)
	 *	- with the username "!root" (console admin login)
	 *	- with Port-Type = Sync (leased line up/down)
	 */
	if (!port_seen ||
	    strncmp(ut.login, "!root", RUT_NAMESIZE) == 0 ||
	    nas_port_type == DV_NAS_PORT_TYPE_SYNC)
		return 0;

	/*
	 *	Enter into the radutmp file.
	 */
	if ((fd = open(radutmp_path, O_RDWR|O_CREAT, 0644)) >= 0) {
		int r;

	 	/*
		 *	Find the entry for this NAS / portno combination.
		 */
		r = 0;
		while (read(fd, &u, sizeof(u)) == sizeof(u)) {
			if (u.nas_address != ut.nas_address ||
			    u.nas_port    != ut.nas_port)
				continue;

			if (status == DV_ACCT_STATUS_TYPE_STOP &&
			    strncmp(ut.session_id, u.session_id, 
			     sizeof(u.session_id)) != 0) {
				/*
				 *	Don't complain if this is not a
				 *	login record (some clients can
				 *	send _only_ logout records).
				 */
				if (u.type == P_LOGIN) {
					radlog(L_ERR,
   _("logout: entry for NAS %s port %d has wrong ID (expected %s found  %s)"),
					    nas_name(nas_address), u.nas_port,
					    ut.session_id,
					    u.session_id);
					r = -1;
					break;
				}
			}

			if (status == DV_ACCT_STATUS_TYPE_START &&
			    strncmp(ut.session_id, u.session_id, 
				    sizeof(u.session_id)) == 0  &&
			    u.time >= ut.time) {
				if (u.type == P_LOGIN) {
					radlog(L_INFO,
		_("login: entry for NAS %s port %d duplicate"),
					    nas_name(nas_address), u.nas_port);
					r = -1;
					dowtmp = 0;
					break;
				} else {
					radlog(L_ERR,
	        _("login: entry for NAS %s port %d wrong order"),
					    nas_name(nas_address), u.nas_port);
					r = -1;
					break;
				}
			}

			/*
			 *	FIXME: the ALIVE record could need
			 *	some more checking, but anyway I'd
			 *	rather rewrite this mess -- miquels.
			 */
			if (status == DV_ACCT_STATUS_TYPE_ALIVE &&
			    strncmp(ut.session_id, u.session_id, 
			     sizeof(u.session_id)) == 0  &&
			    u.type == P_LOGIN) {
				/*
				 *	Keep the original login time.
				 */
				ut.time = u.time;
				if (u.login[0] != 0)
					just_an_update = 1;
			}

			if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
				radlog(L_ERR|L_PERROR, _("negative lseek"));
				lseek(fd, (off_t)0, SEEK_SET);
			}
			r = 1;
			break;
		}

		if (r >= 0 &&  (status == DV_ACCT_STATUS_TYPE_START ||
				status == DV_ACCT_STATUS_TYPE_ALIVE)) {
        		/* Lock the utmp file. */
                        rad_lock(fd, sizeof(ut), 0, SEEK_CUR);

			ut.type = P_LOGIN;
			write(fd, &ut, sizeof(ut));

                        rad_unlock(fd, sizeof(ut), -(off_t)sizeof(ut), SEEK_CUR);
#ifdef USE_NOTIFY
			notify(ut.login, status, NULL);
#endif
		}
		if (status == DV_ACCT_STATUS_TYPE_STOP) {
			ut.type = P_IDLE;
			if (r > 0) {
				u.type = P_IDLE;
				u.duration = ut.time - u.time;
				u.time = ut.time;
				u.delay = ut.delay;
				write(fd, &u, sizeof(u));
			} else if (r == 0) {
				radlog(L_ERR,
		_("logout: login entry for NAS %s port %d not found"),
				nas_name(nas_address), ut.nas_port);
				r = -1;
			}
#ifdef USE_NOTIFY
			notify(ut.login, status, NULL);
#endif
		}
		close(fd);
	} else {
		radlog(L_ERR|L_PERROR, _("can't open %s"), RADUTMP);
		ret = -1;
	}

	/*
	 *	Don't write wtmp if we don't have a username, or
	 *	if this is an update record and the original record
	 *	was already written.
	 */
	if ((status != DV_ACCT_STATUS_TYPE_STOP && ut.login[0] == 0) ||
	    just_an_update)
		dowtmp = 0;

	/*
	 *	Write a RADIUS wtmp log file.
	 */
	if (dowtmp) {
		stat_update(&ut, status);
		write_wtmp(&ut, status);
	} else if (just_an_update) {
		stat_update(&ut, status);
	} else {
		ret = -1;
		stat_inc(acct, authreq->ipaddr, num_norecords);
		radlog(L_NOTICE,
		    _("NOT writing wtmp record (%d) for `%s',NAS %s,port %d"),
		    status, u.login, nas_name(nas_address), ut.nas_port);
	}
	return ret;
}

int
check_acct_dir()
{
	struct stat	st;

	if (stat(radacct_dir, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		else {
			radlog(L_ERR,
				_("%s: not a directory"),
				radacct_dir);
			return 1;
		}
	}
	if (mkdir(radacct_dir, 0755)) {
		radlog(L_CRIT|L_PERROR,
			_("can't create accounting directory `%s'"),
			radacct_dir);
		return 1;
	}
	return 0;
}

int
write_detail(authreq, authtype, f)
	AUTH_REQ *authreq;
	int authtype;
	char *f;
{
	FILE		*outfd;
	char		nasname[MAX_LONGNAME];
	char            *dir, *path;
	char		*s;
	VALUE_PAIR	*pair;
	UINT4		nas;
	NAS		*cl;
	long		curtime;
	int		ret = 0;
	struct stat	st;

	/*
	 * A superfluous precaution, maybe:
	 */
	if (stat(radacct_dir, &st) < 0)
		return 0;
	curtime = time(0);
	
	/*
	 *	Find out the name of this terminal server. We try
	 *	to find the DA_NAS_IP_ADDRESS in the naslist file.
	 *	If that fails, we look for the originating address.
	 *	Only if that fails we resort to a name lookup.
	 */
	cl = NULL;
	nas = authreq->ipaddr;
	if ((pair = pairfind(authreq->request, DA_NAS_IP_ADDRESS)) != NULL)
		nas = pair->lvalue;
	if (authreq->server_ipaddr)
		nas = authreq->server_ipaddr;

	if ((cl = nas_find(nas)) != NULL) {
		if (cl->shortname[0])
			strcpy(nasname, cl->shortname);
		else
			strcpy(nasname, cl->longname);
	}

	if (cl == NULL) {
		s = ip_hostname(nas);
		if (strlen(s) >= sizeof(nasname) || strchr(s, '/'))
			return -1;
		strcpy(nasname, s);
	}
	
	/*
	 *	Create a directory for this nas.
	 */
	dir = mkfilename(radacct_dir, nasname);
	mkdir(dir, 0755);

	/*
	 *	Write Detail file.
	 */
	path = mkfilename(dir, f);
	efree(dir);
	if ((outfd = fopen(path, "a")) == (FILE *)NULL) {
		radlog(L_ERR|L_PERROR, _("can't open %s"), path);
		ret = -1;
	} else {

		/* Post a timestamp */
		fprintf(outfd, ctime(&curtime));

		/* Decide which username to log */
		if (!strip_names) {
			/* user wants a full (non-stripped) name to appear
			 * in detail
			 */
			
			pair = pairfind(authreq->request, DA_ORIG_USER_NAME);
			if (pair) 
				pair->name = "User-Name";
			else
				pair = pairfind(authreq->request, DA_USER_NAME);
			if (pair) {
				fprintf(outfd, "\t");
				fprint_attr_val(outfd, pair);
				fprintf(outfd, "\n");
			}
		}

		/* Write each attribute/value to the log file */
		pair = authreq->request;
		while (pair != (VALUE_PAIR *)NULL) {
			switch (pair->attribute) {
			case DA_PASSWORD:
				break;
			case DA_USER_NAME:
			case DA_ORIG_USER_NAME:
				if (!strip_names)
					break;
			default:
				fprintf(outfd, "\t");
				fprint_attr_val(outfd, pair);
				fprintf(outfd, "\n");
			} 
			pair = pair->next;
		}

		/*
		 *	Add non-protocol attibutes.
		 */
		fprintf(outfd, "\tTimestamp = %ld\n", curtime);
		switch (authtype) {
		    case 0:
			fprintf( outfd, "\tRequest-Authenticator = Verified\n");
			break;
		    case 1:
			fprintf( outfd, "\tRequest-Authenticator = None\n");
			break;
		    case 2:
			fprintf( outfd, "\tRequest-Authenticator = Unverified\n");
			break;
		    default:
			break;
		}
		fprintf( outfd, "\n");
		fclose(outfd);
		ret = 0;
	}
	efree(path);
	
	return ret;
}

int
rad_accounting_orig(authreq, authtype, f)
	AUTH_REQ *authreq;
	int authtype;
	char *f;
{
	int rc;

	rc = write_detail(authreq, authtype, "detail");
#ifdef USE_SQL
	rad_sql_acct(authreq);
#endif
	
	return rc;
}


/*
 *	rad_accounting: call both the old and new style accounting functions.
 */
int
rad_accounting(authreq, activefd)
	AUTH_REQ *authreq;
	int activefd;
{
	int auth;
	char pw_digest[AUTH_PASS_LEN];

	/*
	 *	See if we know this client, then check the
	 *	request authenticator.
	 */
	auth = calc_acctdigest(pw_digest, authreq);
	if (auth < 0) {
		stat_inc(acct, authreq->ipaddr, num_bad_sign);
		return -1;
	}

	huntgroup_access(authreq);
	
	/* Special handling for Ascend-Event-Request
	 */
	if (authreq->code == PW_ASCEND_EVENT_REQUEST) {
		write_detail(authreq, auth, "detail");
		rad_send_reply(PW_ASCEND_EVENT_RESPONSE,
			       authreq, NULL, NULL, activefd);
		stat_inc(acct, authreq->ipaddr, num_resp);
		return 0;
	}

	if (rad_accounting_new(authreq, doradwtmp) == 0 &&
	    rad_accounting_orig(authreq, auth, NULL) == 0) {
		/*
		 *	Now send back an ACK to the NAS.
		 */
		rad_send_reply(PW_ACCOUNTING_RESPONSE,
			       authreq, NULL, NULL, activefd);
		stat_inc(acct, authreq->ipaddr, num_resp);
		return 0;
	}

	return -1;
}


/*
 *	Timeout handler (10 secs)
 */
static int got_alrm;
static void
alrm_handler()
{
	got_alrm = 1;
}

/*
 *	Check one terminal server to see if a user is logged in.
 * Return value:
 *      1 if user is logged in
 *      0 if user is not logged in
 */

static int
rad_check_ts(ut)
	struct radutmp *ut;
{
	int result;
	
	switch (result = check_ts(ut)) {
	case 0:
	case 1:
		return result;

		/* The default return value is a question of policy.
		 * It is defined in /etc/raddb/config
		 */
	default:
		if (config.checkrad_assume_logged) 
			radlog(L_NOTICE, _("assuming `%s' is logged in"),
			       ut->login);
		else
			radlog(L_NOTICE, _("assuming `%s' is NOT logged in"),
			       ut->login);
		return config.checkrad_assume_logged;
	}
	/*NOTREACHED*/
}

/* Return value: that of CHECKRAD process, i.e. 1 means true (user FOUND)
 * 0 means false (user NOT found)
 */
static int
check_ts(ut)
	struct radutmp *ut;
{
	int	pid, st, e;
	int	n;
	NAS	*nas;
	char	address[DOTTED_QUAD_LEN];
	char	port[32];
	char	session_id[RUT_IDSIZE+1];
	void	(*handler)(int);

	/*
	 *	Find NAS type.
	 */
	if ((nas = nas_find(ntohl(ut->nas_address))) == NULL) {
		radlog(L_NOTICE, _("check_ts(): unknown NAS"));
		return 0; 
	}

	/*
	 *	Fork.
	 */
	handler = signal(SIGCHLD, SIG_DFL);
	if ((pid = fork()) < 0) {
		radlog(L_ERR|L_PERROR, _("check_ts(): can't fork"));
		signal(SIGCHLD, handler);
		return -1;
	}

	if (pid > 0) {
		/*
		 *	Parent - Wait for checkrad to terminate.
		 *	We timeout in 10 seconds.
		 */
		got_alrm = 0;
		signal(SIGALRM, alrm_handler);
		alarm(10);
		while ((e = waitpid(pid, &st, 0)) != pid)
			if (e < 0 && (errno != EINTR || got_alrm))
				break;
		alarm(0);
		signal(SIGCHLD, handler);
		if (got_alrm) {
			kill(pid, SIGTERM);
			sleep(1);
			kill(pid, SIGKILL);
			radlog(L_WARN, _("check_ts(): timeout waiting for checkrad"));
			return -1;
		}
		if (e < 0) {
			radlog(L_ERR|L_PERROR, 
				_("check_ts(): error in waitpid()"));
			return -1;
		}
		debug(10,
			("got response %d", WEXITSTATUS(st))); 
		return WEXITSTATUS(st);
	}

	/*
	 *	Child - exec checkrad with the right parameters.
	 */
	for (n = 32; n >= 3; n--)
		close(n);

	ipaddr2str(address, ntohl(ut->nas_address));
	sprintf(port, "%d", ut->nas_port);
	strncpy(session_id, ut->session_id, RUT_IDSIZE);
	session_id[RUT_IDSIZE] = 0;

	debug(10,
		("starting checkrad -d %s -t %s -h %s -p %s -u %s -s %s",
		radius_dir,
	    	nas->nastype, address, port, ut->login, session_id));
	execl(CHECKRAD, "checkrad", 
		"-d", radius_dir,	
		"-t", nas->nastype, 
		"-h", address, 
		"-p", port,
		"-u", ut->orig_login, 
		"-s", session_id, NULL);
	radlog(L_ERR, "check_ts(): exec %s: %s", CHECKRAD, strerror(errno));

	/*
	 *	Exit - 2 means "some error occured".
	 */
	exit(2);
}


/*
 *	See if a user is already logged in.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. telnet).
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int
rad_check_multi(name, request, maxsimul)
	char *name;
	VALUE_PAIR *request;
	int maxsimul;
{
	int		fd;
	int		count;
	struct radutmp	u, empty;
	VALUE_PAIR	*fra;
	int		mpp = 1;
	UINT4		ipno = 0;
	
	if ((fd = open(radutmp_path, O_CREAT|O_RDWR, 0644)) < 0)
		return 0;

	/*
	 *	We don't lock in the first pass.
	 */
	count = 0;
	while(read(fd, &u, sizeof(u)) == sizeof(u))
		if (strncmp(name, u.login, RUT_NAMESIZE) == 0
		    && u.type == P_LOGIN) {
			count++;
		}

	if (count < maxsimul) {
		close(fd);
		return 0;
	}
	lseek(fd, (off_t)0, SEEK_SET);

	/*
	 *	Setup some stuff, like for MPP detection.
	 */
	if ((fra = pairfind(request, DA_FRAMED_IP_ADDRESS)) != NULL)
		ipno = htonl(fra->lvalue);
	memset(&empty, 0, sizeof(empty));


	/*
	 *	Allright, there are too many concurrent logins.
	 *	Check all registered logins by querying the
	 *	terminal server directly.
	 */
	count = 0;

	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if (strncmp(name, u.login, RUT_NAMESIZE) == 0
		    && u.type == P_LOGIN) {
			if (rad_check_ts(&u) == 1) {
				count++;
				/*
				 *	Does it look like a MPP attempt?
				 */
				if (strchr("SCPA", u.proto) &&
				    ipno && u.framed_address == ipno)
					mpp = 1;
			} else {
				/*
				 *	False record - zap it.
				 */

				lseek(fd, -(off_t)sizeof(u), SEEK_CUR);

                                /* lock the file while writing. */
	                        rad_lock(fd, sizeof(empty), 0, SEEK_CUR);
                                write(fd, &empty, sizeof(empty));
                                rad_unlock(fd, sizeof(empty),
					   -(off_t)sizeof(empty), SEEK_CUR);

				write_wtmp(&u, DV_ACCT_STATUS_TYPE_STOP);
			}
		}
	}
	close(fd);

	return (count < maxsimul) ? 0 : mpp;
}

int
write_nas_restart(status, addr)
	int status;
	UINT4 addr;
{
	struct radutmp ut;

	bzero(&ut, sizeof(ut));
	if (status == DV_ACCT_STATUS_TYPE_ACCOUNTING_ON) 
		ut.type = P_NAS_START;
	else
		ut.type = P_NAS_SHUTDOWN;
	ut.nas_address = addr;
	time(&ut.time);
	return write_wtmp(&ut, status);
}











