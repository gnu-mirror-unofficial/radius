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

#define RADIUS_MODULE 6
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#if defined(PWD_SHADOW)
#include <shadow.h>
#endif /* PWD_SHADOW */

#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#endif

#ifdef OSFC2
# include <sys/security.h>
# include <prot.h>
#endif

#include <radiusd.h>
#if defined(USE_SQL)
# include <radsql.h>
#endif
#include <timestr.h>

#if !defined(__linux__) && !defined(__GLIBC__)
  extern char *crypt();
#endif

static int pw_expired(UINT4 exptime);
static int check_disable(char *username, char **user_msg);
static int check_expiration(VALUE_PAIR *check_item, char **user_msg);
static int unix_pass(char *name, char *passwd);

/*
 *	Tests to see if the users password has expired.
 *
 *	Return: Number of days before expiration if a warning is required
 *		otherwise 0 for success and -1 for failure.
 */
static int
pw_expired(exptime)
	UINT4 exptime;
{
	struct timeval	tp;
	struct timezone	tzp;
	UINT4		exp_remain;
	int		exp_remain_int;

	gettimeofday(&tp, &tzp);
	if (tp.tv_sec > exptime)
		return -1;

	if (warning_seconds != 0) {
		if (tp.tv_sec > exptime - warning_seconds) {
			exp_remain = exptime - tp.tv_sec;
			exp_remain /= (UINT4)SECONDS_PER_DAY;
			exp_remain_int = exp_remain;
			return exp_remain_int;
		}
	}
	return 0;
}

/*
 * Check if the username is valid. Valid usernames consist of 
 * alphanumeric characters and symbols from valid_char[]
 * array
 */
int
check_user_name(p)
	char *p;
{
	static char valid_char[] = ".-_!@";
	for (; *p && (isalnum(*p) || strchr(valid_char, *p)); p++)
		;
	return *p;
}

int
check_disable(username, user_msg)
	char *username;
	char **user_msg;
{
	if (get_deny(username)) {
		*user_msg = make_string(
			    _("Sorry, your account is currently closed\r\n"));
		return -1;
	}
	return 0;
}

/*
 *	Check if account has expired, and if user may login now.
 */
int
check_expiration(check_item, user_msg)
	VALUE_PAIR *check_item;
	char **user_msg;
{
	int result, rc;
	VALUE_PAIR *pair;
	char umsg[80];
	
	result = AUTH_OK;
	if (pair = pairfind(check_item, DA_EXPIRATION)) {
		rc = pw_expired(pair->lvalue);
		if (rc < 0) {
			result = AUTH_FAIL;
			*user_msg = make_string(_("Password Has Expired\r\n"));
		} else if (rc > 0) {
			radsprintf(umsg, sizeof(umsg),
				   _("Password Will Expire in %d Days\r\n"),
				   rc);
			*user_msg = make_string(umsg);
		}
	}

	return result;
}
/*
 *	Check the users password against the standard UNIX
 *	password table.
 */
int
unix_pass(name, passwd)
	char *name;
	char *passwd;
{
	struct passwd	*pwd;
	char		*encpw;
	char		*encrypted_pass;
#if defined(PWD_SHADOW)
# if defined(M_UNIX)
	struct passwd	*spwd;
# else
	struct spwd	*spwd;
# endif
#endif /* PWD_SHADOW */
#ifdef OSFC2
	struct pr_passwd *pr_pw;

	if ((pr_pw = getprpwnam(name)) == NULL)
		return -1;
	encrypted_pass = pr_pw->ufld.fd_encrypt;
#else /* OSFC2 */
	/*
	 *	Get encrypted password from password file
	 */
	if ((pwd = getpwnam(name)) == NULL) {
		return -1;
	}
	encrypted_pass = pwd->pw_passwd;
#endif /* OSFC2 */

#if defined(PWD_SHADOW)
	/*
	 *      See if there is a shadow password.
	 */
	if ((spwd = getspnam(name)) != NULL)
# if defined(M_UNIX)
		encrypted_pass = spwd->pw_passwd;
# else
		encrypted_pass = spwd->sp_pwdp;
# endif	/* M_UNIX */
#endif	/* PWD_SHADOW */

#ifdef DENY_SHELL
	/*
	 * Users with a certain shell are always denied access.
	 */
	if (strcmp(pwd->pw_shell, DENY_SHELL) == 0) {
		radlog(L_AUTH, _("unix_pass: [%s]: invalid shell"), name);
		return -1;
	}
#endif

#if defined(PWD_SHADOW) && !defined(M_UNIX)
	/*
	 *      Check if password has expired.
	 */
	if (spwd && spwd->sp_expire > 0 &&
	    (time(NULL) / 86400) > spwd->sp_expire) {
		radlog(L_AUTH, _("unix_pass: [%s]: password has expired"), name);
		return -1;
	}
#endif

#ifdef OSFC2
	/*
	 *	Check if account is locked.
	 */
	if (pr_pw->uflg.fg_lock != 1) {
		radlog(L_AUTH, _("unix_pass: [%s]: account locked"), name);
		return -1;
	}
#endif /* OSFC2 */

	/*
	 * Forbid logins on passwordless accounts 
	 */
	if (encrypted_pass[0] == 0)
		return 0;

	/*
	 * Check encrypted password.
	 */
	encpw = md5crypt(passwd, encrypted_pass);
	if (strcmp(encpw, encrypted_pass))
		return -1;

	return 0;
}


/*
 *	Check password.
 *
 *	Returns:	AUTH_OK      OK
 *			AUTH_FAIL    Password fail
 *                      AUTH_NOUSER  No such user 
 *			AUTH_REJECT  Rejected
 *			
 */
/*ARGSUSED*/
int
rad_check_password(authreq, activefd, check_item, namepair,
		   pw_digest, user_msg, userpass)
	AUTH_REQ   *authreq;
	int        activefd;
	VALUE_PAIR *check_item;
	VALUE_PAIR *namepair;
	u_char     *pw_digest;
	char       **user_msg;
	char       *userpass;
{
	char		string[AUTH_STRING_LEN];
	char		*ptr;
	char		name[AUTH_STRING_LEN];
	VALUE_PAIR	*auth_type_pair;
	VALUE_PAIR	*password_pair;
	VALUE_PAIR	*auth_item;
	VALUE_PAIR	*tmp;
	int		auth_type = -1;
	int		i;
	int		result;
        VALUE_PAIR      *p;
	char            *authdata = NULL;
	
	result = AUTH_OK;
	userpass[0] = 0;
	string[0] = 0;

	/*
	 *	Look for matching check items. We skip the whole lot
	 *	if the authentication type is DV_AUTH_TYPE_ACCEPT or
	 *	DV_AUTH_TYPE_REJECT.
	 */
	if ((auth_type_pair = pairfind(check_item, DA_AUTH_TYPE)) != NULL)
		auth_type = auth_type_pair->lvalue;

	if (auth_type == DV_AUTH_TYPE_ACCEPT)
		return AUTH_OK;

	if (auth_type == DV_AUTH_TYPE_REJECT) {
		*user_msg = NULL;
		return AUTH_REJECT;
	}

        if ((p = pairfind(check_item, DA_AUTH_DATA)) != NULL) {
		authdata = p->strvalue;
        }
	
	/*
	 *	Find the password sent by the user. It SHOULD be there,
	 *	if it's not authentication fails.
	 *
	 *	FIXME: add MS-CHAP support ?
	 */
	if ((auth_item = pairfind(authreq->request, DA_CHAP_PASSWORD)) == NULL)
		auth_item = pairfind(authreq->request, DA_PASSWORD);
	if (auth_item == NULL)
		return AUTH_FAIL;

	/*
	 *	Find the password from the users file.
	 */
	if ((password_pair = pairfind(check_item, DA_CRYPT_PASSWORD)) != NULL)
		auth_type = DV_AUTH_TYPE_CRYPT_LOCAL;
	else
		password_pair = pairfind(check_item, DA_PASSWORD);

	/*
	 *	See if there was a Prefix or Suffix included.
	 */
	strip_username(1, namepair->strvalue, check_item, name);

	/*
	 *	Decrypt the password.
	 */
	if (auth_item != NULL && auth_item->attribute == DA_PASSWORD) {
		if (auth_item->strlength == 0)
			string[0] = 0;
		else {
			memcpy(string, auth_item->strvalue, AUTH_PASS_LEN);
			for (i = 0;i < AUTH_PASS_LEN;i++) {
				string[i] ^= pw_digest[i];
			}
			string[AUTH_PASS_LEN] = '\0';
		}
		strcpy(userpass, string);
	}

	debug(1,
		("auth_type=%d, string=%s, namepair=%s, password_pair=%s",
		 auth_type, string, name,
		 password_pair ? password_pair->strvalue : ""));

	if ((p = pairfind(check_item, DA_AUTH_DATA)) != NULL) 
		authdata = p->strvalue;

	switch (auth_type) {
		case DV_AUTH_TYPE_SYSTEM:
			debug(1, ("  auth: System"));
			/*
			 *	Check the password against /etc/passwd.
			 */
			if (unix_pass(name, string) != 0)
				result = AUTH_FAIL;
			break;
		case DV_AUTH_TYPE_PAM:
#ifdef USE_PAM
			debug(1, ("  auth: Pam"));
			/*
			 * Provide defaults for authdata
			 */
			if (authdata == NULL &&
			    (p = pairfind(check_item, DA_PAM_AUTH)) != NULL) {
				authdata = p->strvalue;
			}
			authdata = authdata ? authdata : PAM_DEFAULT_TYPE;
			if (pam_pass(name, string, authdata, user_msg) != 0)
				result = AUTH_FAIL;
#else
			radlog(L_ERR,
			       _("%s: PAM authentication not available"),
			       name);
			result = AUTH_NOUSER;
#endif
			break;
		case DV_AUTH_TYPE_MYSQL:
#ifdef USE_SQL
			result = rad_sql_pass(authreq, authdata, string);
#else
			radlog(L_ERR,
			       _("%s: MYSQL authentication not available"),
			       name);
			result = AUTH_NOUSER;
#endif
			break;
		case DV_AUTH_TYPE_CRYPT_LOCAL:
			debug(1, ("  auth: Crypt"));
			if (password_pair == NULL) {
				result = string[0] ? AUTH_FAIL : AUTH_OK;
				break;
			}
			if (strcmp(password_pair->strvalue,
			    md5crypt(string, password_pair->strvalue)) != 0)
				result = AUTH_FAIL;
			break;
		case DV_AUTH_TYPE_LOCAL:
			debug(1, ("  auth: Local"));
			/*
			 *	Local password is just plain text.
	 		 */
			if (auth_item->attribute != DA_CHAP_PASSWORD) {
				/*
				 *	Plain text password.
				 */
				if (password_pair == NULL ||
				    strcmp(password_pair->strvalue, string)!=0)
					result = AUTH_FAIL;
				break;
			}

			/*
			 *	CHAP - calculate MD5 sum over CHAP-ID,
			 *	plain-text password and the Chap-Challenge.
			 *	Compare to Chap-Response (strvalue + 1).
			 *
			 *	FIXME: might not work with Ascend because
			 *	we use vp->strlength, and Ascend gear likes
			 *	to send an extra '\0' in the string!
			 */
			strcpy(string, "{chap-password}");
			if (password_pair == NULL) {
				result= AUTH_FAIL;
				break;
			}
			i = 0;
			ptr = string;
			*ptr++ = *auth_item->strvalue;
			i++;
			memcpy(ptr, password_pair->strvalue,
				password_pair->strlength);
			ptr += password_pair->strlength;
			i += password_pair->strlength;
			/*
			 *	Use Chap-Challenge pair if present,
			 *	Request-Authenticator otherwise.
			 */
			if ((tmp = pairfind(authreq->request,
					    DA_CHAP_CHALLENGE)) != NULL) {
				memcpy(ptr, tmp->strvalue, tmp->strlength);
				i += tmp->strlength;
			} else {
				memcpy(ptr, authreq->vector, AUTH_VECTOR_LEN);
				i += AUTH_VECTOR_LEN;
			}
			md5_calc(pw_digest, (u_char*) string, i);

			/*
			 *	Compare them
			 */
			if (memcmp(pw_digest, auth_item->strvalue + 1,
					CHAP_VALUE_LENGTH) != 0)
				result = AUTH_FAIL;
			else
				strcpy(userpass, password_pair->strvalue);
			break;
		default:
			result = AUTH_FAIL;
			break;
	}

	/*??
	if (result < 0)
		*user_msg = NULL;
	*/
	return result;
}

/*
 *	Initial step of authentication.
 *	Find username, calculate MD5 digest, and
 *	process the hints and huntgroups file.
 */
int
rad_auth_init(authreq, activefd)
	AUTH_REQ *authreq;
	int       activefd;
{
	VALUE_PAIR	*namepair;
#ifdef USE_SQL
	VALUE_PAIR	*p;
#endif

	/*
	 *	Get the username from the request
	 */
	namepair = pairfind(authreq->request, DA_USER_NAME);

	if ((namepair == (VALUE_PAIR *)NULL) || 
	   (strlen(namepair->strvalue) <= 0)) {
		radlog(L_ERR, _("No username: [] (from nas %s)"),
		       nas_name2(authreq));
		stat_inc(auth, authreq->ipaddr, num_bad_req);
		authfree(authreq);
		return -1;
	}
	debug(1,("checking username: %s", namepair->strvalue));
	if (check_user_name(namepair->strvalue)) {
		radlog(L_AUTH, _("Malformed username: [%s] (from nas %s)"),
		       namepair->strvalue,
		       nas_name2(authreq));
		stat_inc(auth, authreq->ipaddr, num_bad_req);
		authfree(authreq);
		return -1;
	}
		
	/*
	 *	Verify the client and Calculate the MD5 Password Digest
	 */
	if (calc_digest(authreq->digest, authreq) != 0) {
		/*
		 *	We don't respond when this fails
		 */
		radlog(L_NOTICE,
		       _("from client %s - Security Breach: %s"),
		       client_name(authreq->ipaddr), namepair->strvalue);
		stat_inc(auth, authreq->ipaddr, num_bad_auth);
		authfree(authreq);
		return -1;
	}

#ifdef USE_SQL
	if (p = create_pair(DA_QUEUE_ID, 0, NULL, (qid_t)authreq))
		pairadd(&authreq->request, p);
#endif
	/*
	 *	Add any specific attributes for this username.
	 */
	hints_setup(authreq->request);

	if (auth_detail)
		write_detail(authreq, -1, "detail.auth");

	/*
	 *	See if the user has access to this huntgroup.
	 */
	if (!huntgroup_access(authreq)) {
		radlog(L_AUTH, _("No huntgroup access: [%s] (from nas %s)"),
			namepair->strvalue, nas_name2(authreq));
		rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
			       authreq->request, NULL, activefd);
		authfree(authreq);
		return -1;
	}

	return 0;
}

/* ****************************************************************************
 * Authentication state machine.
 */

enum auth_state {
	as_init,
	as_validate,
	as_service, 
	as_disable, 
	as_service_type,
	as_realmuse,
	as_simuse, 
	as_time, 
	as_ttl, 
	as_ipaddr, 
	as_exec_wait, 
	as_cleanup_cbkid, 
	as_menu,
	as_ack, 
	as_exec_nowait, 
	as_stop, 
	as_reject,
	AS_COUNT
};

enum list_id {
	L_null,
	L_req,
	L_reply,
	L_check
};

typedef struct auth_mach {
	AUTH_REQ   *req;
	VALUE_PAIR *user_check;
	VALUE_PAIR *user_reply;
	VALUE_PAIR *proxy_pairs;
	int        activefd;
	
	VALUE_PAIR *namepair;
	VALUE_PAIR *check_pair;
	VALUE_PAIR *timeout_pair;
	char       userpass[AUTH_STRING_LEN];
	char       *user_msg;
	
	char       *clid;
	enum auth_state state;
} MACH;

static void sfn_init(MACH*);
static void sfn_validate(MACH*);
static void sfn_service(MACH*);
static void sfn_disable(MACH*);
static void sfn_service_type(MACH*);
static void sfn_realmuse(MACH*);
static void sfn_simuse(MACH*);
static void sfn_time(MACH*);
static void sfn_ttl(MACH*);
static void sfn_ipaddr(MACH*);
static void sfn_exec_wait(MACH*);
static void sfn_cleanup_cbkid(MACH*);
static void sfn_menu(MACH*);
static void sfn_ack(MACH*);
static void sfn_exec_nowait(MACH*);
static void sfn_reject(MACH*);
static VALUE_PAIR *timeout_pair(MACH *m);


struct auth_state_s {
	enum auth_state this;
	enum auth_state next;
	int             attr;
	enum list_id    list;
	void            (*sfn)(MACH*);
};

struct auth_state_s states[] = {
	as_init,         as_validate,
	                 0,               L_null,     sfn_init,

	as_validate,     as_service,
	                 0,               L_null,     sfn_validate,
	
	as_service,      as_disable,
	                 DA_SERVICE_TYPE, L_req, sfn_service,
	
	as_disable,      as_service_type,
	                 0,               L_null,     sfn_disable,
	
	as_service_type, as_realmuse,
	                 DA_SERVICE_TYPE, L_reply, sfn_service_type,

	as_realmuse,     as_simuse,
	                 0,               L_null,     sfn_realmuse, 
	
	as_simuse,       as_time,
	                 DA_SIMULTANEOUS_USE, L_check, sfn_simuse,
	
	as_time,         as_ttl,
	                 DA_LOGIN_TIME,   L_check, sfn_time,
	
	as_ttl,          as_ipaddr,
	                 0,               L_null, sfn_ttl,
	
	as_ipaddr,       as_exec_wait,
	                 0,               L_null, sfn_ipaddr,
	
	as_exec_wait,    as_cleanup_cbkid,
	                 DA_EXEC_PROGRAM_WAIT, L_reply, sfn_exec_wait,
	
	as_cleanup_cbkid,as_menu,
	                 DA_CALLBACK_ID,  L_reply, sfn_cleanup_cbkid,
	
	as_menu,         as_ack,
	                 DA_MENU,         L_reply, sfn_menu,
	
	as_ack,          as_exec_nowait,
	                 0,               L_null, sfn_ack,
	
	as_exec_nowait,  as_stop,
	                 DA_EXEC_PROGRAM, L_reply, sfn_exec_nowait,
	
	as_stop,         as_stop,
	                 0,               L_null, NULL,
	
	as_reject,       as_stop,
	                 0,               L_null, sfn_reject,
};

int
rad_authenticate(authreq, activefd)
	AUTH_REQ  *authreq;
	int        activefd;
{
	enum auth_state oldstate;
	struct auth_state_s *sp;
	struct auth_mach m;

#ifdef USE_LIVINGSTON_MENUS
	VALUE_PAIR *pair_ptr;

	/*
	 * If the request is processing a menu, service it here.
	 */
	if ((pair_ptr = pairfind(authreq->request, DA_STATE)) != NULL &&
	    strncmp(pair_ptr->strvalue, "MENU=", 5) == 0) {
	    process_menu(authreq, activefd, authreq->digest);
	    return 0;
	}
#endif

	m.req = authreq;
	m.activefd = activefd;
	m.user_check = NULL;
	m.user_reply = NULL;
	m.proxy_pairs= NULL;
	m.check_pair = NULL;
	m.timeout_pair = NULL;
	m.user_msg   = NULL;
	/*FIXME: this should have been cached by rad_auth_init */
	m.namepair = pairfind(m.req->request, DA_USER_NAME);

	debug(1, ("auth: %s", m.namepair->strvalue)); 
	m.state = as_init;

	while (m.state != as_stop) {
		sp = &states[m.state];
		oldstate = m.state;
		if (sp->attr) {
			VALUE_PAIR *p;
			
			switch (sp->list) {
			case L_req:
				p = m.req->request;
				break;
			case L_check:
				p = m.user_check;
				break;
			case L_reply:
				p = m.user_reply;
				break;
			default:
				abort();
			}
			if (p = pairfind(p, sp->attr))
				m.check_pair = p;
			else {
				m.state = sp->next;
				continue;
			}
		}
		(*sp->sfn)(&m);
		/* default action: */
		if (oldstate == m.state) 
			m.state = sp->next;
	}

	/* Cleanup */
	pairfree(m.user_check);
	pairfree(m.user_reply);
	pairfree(m.proxy_pairs);
	if (m.user_msg)
		free_string(m.user_msg);
	bzero(m.userpass, sizeof(m.userpass));
	return 0;
}

#if RADIUS_DEBUG
# define newstate(s) do {\
             debug(2, ("%d -> %d", m->state, s));\
             m->state = s;\
  } while (0)
#else
# define newstate(s) m->state = s
#endif

void
sfn_init(m)
	MACH *m;
{
	int proxied = 0;
	AUTH_REQ *authreq = m->req;
	VALUE_PAIR *pair_ptr;
	
	/*
	 *	Move the proxy_state A/V pairs somewhere else.
	 */
	pairmove2(&m->proxy_pairs, &authreq->request, DA_PROXY_STATE);

	/*
	 *	If this request got proxied to another server, we need
	 *	to add an initial Auth-Type: Auth-Accept for success,
	 *	Auth-Reject for fail. We also need to add the reply
	 *	pairs from the server to the initial reply.
	 */
	if (authreq->server_code == PW_AUTHENTICATION_REJECT ||
	    authreq->server_code == PW_AUTHENTICATION_ACK) {
		m->user_check = create_pair(DA_AUTH_TYPE, 0, NULL, 0);
		proxied = 1;
	}
	if (authreq->server_code == PW_AUTHENTICATION_REJECT)
		m->user_check->lvalue = DV_AUTH_TYPE_REJECT;
	if (authreq->server_code == PW_AUTHENTICATION_ACK)
		m->user_check->lvalue = DV_AUTH_TYPE_ACCEPT;

	if (authreq->server_reply) {
		m->user_reply = authreq->server_reply;
		authreq->server_reply = NULL;
	}

	if (pair_ptr = pairfind(authreq->request, DA_CALLING_STATION_ID)) 
		m->clid = pair_ptr->strvalue;
	else
		m->clid = _("unknown");

	/*
	 *	Get the user from the database
	 */
	if (!proxied &&
	    user_find(m->namepair->strvalue, authreq->request,
		      &m->user_check, &m->user_reply) != 0) {
		radlog(L_AUTH, _("Invalid user: [%s] CLID %s (from nas %s)"),
		       m->namepair->strvalue,
		       m->clid,
		       nas_name2(authreq));

		/* Send reject packet with proxy-pairs as a reply */
		newstate(as_reject);
		pairfree(m->user_reply);
		m->user_reply = m->proxy_pairs;
		m->proxy_pairs = NULL;
	}
}

void
sfn_validate(m)
	MACH *m;
{
	AUTH_REQ *authreq = m->req;
	VALUE_PAIR *p;
	int rc;
	
	/*
	 *	Validate the user
	 */
	if ((rc = check_expiration(m->user_check, &m->user_msg)) >= 0) {
		rc = rad_check_password(authreq, m->activefd,
					m->user_check,
					m->namepair, authreq->digest,
					&m->user_msg, m->userpass);

		if (rc != AUTH_OK) { 
			stat_inc(auth, authreq->ipaddr, num_rejects);
			newstate(as_reject);
			
			switch (rc) {
			case AUTH_REJECT:
				radlog(L_AUTH,
			      _("Rejected user: [%s] CLID %s (from nas %s)"),
				       m->namepair->strvalue,
				       m->clid,
				       nas_name2(authreq));
				return;
				
			case AUTH_NOUSER:
				radlog(L_AUTH,
			       _("Invalid user: [%s] CLID %s (from nas %s)"),
				       m->namepair->strvalue,
				       m->clid,
				       nas_name2(authreq));
				return;
				
			case AUTH_FAIL:
				break;
			}
		}		
              /*if (p = pairfind(m->user_reply, DA_REPLY_MESSAGE))
			m->user_msg = dup_string(p->strvalue);*/
	}

	pairmove2(&m->user_reply, &m->proxy_pairs, DA_PROXY_STATE);

	if (rc != AUTH_OK) {
		/*
		 *	Failed to validate the user.
		 */
		newstate(as_reject);
		if (log_mode & RLOG_AUTH) {
			if (log_mode & RLOG_FAILED_PASS) {
				radlog(L_AUTH,
				       _("Login incorrect: [%s/%s] CLID %s (from nas %s)"),
				       m->namepair->strvalue,
				       m->userpass,
				       m->clid,
				       nas_name2(authreq));
			} else {			
				radlog(L_AUTH,
				       _("Login incorrect: [%s] CLID %s (from nas %s)"),
				       m->namepair->strvalue,
				       m->clid,
				       nas_name2(authreq));
			}
		}
	}
}

void
sfn_service(m)
	MACH *m;
{
	/* FIXME: Other service types should also be handled,
	 *        I suppose       -- Gray
	 */
	if (m->check_pair->lvalue != DV_SERVICE_TYPE_AUTHENTICATE_ONLY)
		return;
	if (log_mode & RLOG_AUTH) {
		radlog(L_AUTH,
		       _("Authentication OK: [%s%s%s] (from nas %s)"),
		       m->namepair->strvalue,
		       (log_mode & RLOG_AUTH_PASS)
		                ? "/" : "",
		       (log_mode & RLOG_AUTH_PASS)
		                ? m->userpass : "",
		       nas_name2(m->req));
	}
	newstate(as_ack);
}

void
sfn_disable(m)
	MACH *m;
{
	if (check_disable(m->namepair->strvalue, &m->user_msg)) {
		radlog(L_AUTH, "Account disabled: [%s]",
		       m->namepair->strvalue);
		newstate(as_reject);
	}
}

void
sfn_service_type(m)
	MACH *m;
{
	if (m->check_pair->lvalue == DV_SERVICE_TYPE_AUTHENTICATE_ONLY) {
		radlog(L_AUTH,
		       "Login rejected [%s]. Authenticate only user.",
		       m->namepair->strvalue); 
		m->user_msg = make_string(_("\r\nAccess denied\r\n"));
		newstate(as_reject);
	}
}

void
sfn_realmuse(m)
	MACH *m;
{
	if (!m->req->realm)
		return;
	
	if (rad_check_realm(m->req->realm) == 0)
		return;
	m->user_msg = make_string(
		_("\r\nRealm quota exceeded - access denied\r\n"));
	radlog(L_AUTH,
   _("Login failed: [%s]: realm quota exceeded for %s: CLID %s (from nas %s)"),
	       m->namepair->strvalue,
	       m->req->realm,
	       m->clid,
	       nas_name2(m->req));
	newstate(as_reject);
}

void
sfn_simuse(m)
	MACH *m;
{
	char  name[AUTH_STRING_LEN];
	int   rc;
	char  umsg[AUTH_STRING_LEN];

	strip_username(strip_names,
		       m->namepair->strvalue, m->user_check, name);
	if ((rc = rad_check_multi(name, m->req->request,
				  m->check_pair->lvalue)) == 0)
		return;
	
	if (m->check_pair->lvalue > 1) {
		radsprintf(umsg, sizeof(umsg),
	      _("\r\nYou are already logged in %d times  - access denied\r\n"),
			(int)m->check_pair->lvalue);
		m->user_msg = make_string(umsg);
	} else {
		m->user_msg = make_string(
		      _("\r\nYou are already logged in - access denied\r\n"));
	}

	radlog(L_WARN,
	       _("Multiple logins: [%s] (from nas %s) max. %ld%s"),
	       m->namepair->strvalue,
	       nas_name2(m->req),
	       m->check_pair->lvalue,
	       rc == 2 ? _(" [MPP attempt]") : "");
	newstate(as_reject);
}

VALUE_PAIR *
timeout_pair(m)
	MACH *m;
{
	if (!m->timeout_pair &&
	    !(m->timeout_pair = pairfind(m->user_reply, DA_SESSION_TIMEOUT))) {
		m->timeout_pair = create_pair(DA_SESSION_TIMEOUT,
					      0, NULL, 0);
		pairadd(&m->user_reply, m->timeout_pair);
	}
	return m->timeout_pair;
}

void
sfn_time(m)
	MACH *m;
{
	int rc;
	time_t t;
	unsigned rest;
	
	time(&t);
	rc = ts_check(m->check_pair->strvalue, &t, &rest, NULL);
	if (rc == 1) {
		/*
		 *	User called outside allowed time interval.
		 */
		m->user_msg = make_string(
		      _("You are calling outside your allowed timespan\r\n"));
		radlog(L_ERR,
       _("Outside allowed timespan: [%s] (from nas %s) time allowed: %s"),
		       m->namepair->strvalue,
		       nas_name2(m->req),
		       m->check_pair->strvalue);
		newstate(as_reject);
	} else if (rc == 0) {
		/*
		 *	User is allowed, but set Session-Timeout.
		 */
		timeout_pair(m)->lvalue = rest;
		debug(2, ("user %s, span %s, timeout %d",
			  m->namepair->strvalue,
                          m->check_pair->strvalue,
                          rest));
	}
}

/*ARGSUSED*/
void
sfn_ttl(m)
	MACH *m;
{
#ifdef USE_NOTIFY	
	long r;
	if (timetolive(m->namepair->strvalue, &r) == 0) {
		if (r > 0) {
			timeout_pair(m)->lvalue = r;
		} else {
			radlog(L_AUTH, _("Zero time to live: [%s]"),
			       m->namepair->strvalue); 
			m->user_msg = make_string(
			 _("\r\nSorry, your account is currently closed\r\n"));
			newstate(as_reject);
		}
	}
#endif
}

void
sfn_ipaddr(m)
	MACH *m;
{
	VALUE_PAIR *p, *tmp, *pp;
	
	/* Assign an IP if necessary */
	if (!pairfind(m->user_reply, DA_FRAMED_IP_ADDRESS)) {
#if 0
		/* **************************************************
		 * Keep it here until IP allocation is ready
		 */
		if (p = alloc_ip_pair(m->namepair->strvalue, m->req))
			pairadd(&m->user_reply, p);
		else
#endif	
		if (p = pairfind(m->req->request, DA_FRAMED_IP_ADDRESS)) {
			/* termserver hint */
			pairadd(&m->user_reply, pairdup(p));
			if (p = pairfind(m->req->request,
					 DA_ADD_PORT_TO_IP_ADDRESS))
				pairadd(&m->user_reply, pairdup(p));
		}
	}
	
	if ((p = pairfind(m->user_reply, DA_FRAMED_IP_ADDRESS)) &&
	    (tmp = pairfind(m->user_reply, DA_ADD_PORT_TO_IP_ADDRESS)) &&
	    tmp->lvalue &&
	    (pp = pairfind(m->req->request, DA_NAS_PORT_ID)))
		/* NOTE: This only works because IP numbers are stored in
		 * host order throughout the program.
		 */
		p->lvalue += pp->lvalue;
		
	pairdelete(&m->user_reply, DA_ADD_PORT_TO_IP_ADDRESS);
}

void
sfn_exec_wait(m)
	MACH *m;
{
	if (radius_exec_program(m->check_pair->strvalue,
				m->req->request,
				&m->user_reply,
				1,
				&m->user_msg) != 0) {
		/*
		 *	Error. radius_exec_program() returns -1 on
		 *	fork/exec errors, or >0 if the exec'ed program
		 *	had a non-zero exit status.
		 */

		newstate(as_reject);

		if (!m->user_msg)
			m->user_msg = make_string(
			     _("\r\nAccess denied (external check failed)."));

		if (log_mode & RLOG_AUTH) {
			radlog(L_AUTH,
	  _("Login incorrect: [%s] CLID %s (from nas %s): external check failed"),
			       m->namepair->strvalue,
			       m->clid,
			       nas_name2(m->req));
		}
	}
}

void
sfn_exec_nowait(m)
	MACH *m;
{
	/*FIXME: do we need to pass user_reply here? */
	radius_exec_program(m->check_pair->strvalue,
			    m->req->request, &m->user_reply,
			    0, NULL);
}

void
sfn_cleanup_cbkid(m)
	MACH *m;
{
	static int delete_pairs[] = {
		DA_FRAMED_PROTOCOL,
		DA_FRAMED_IP_ADDRESS,
		DA_FRAMED_IP_NETMASK,
		DA_FRAMED_ROUTE,
		DA_FRAMED_MTU,
		DA_FRAMED_COMPRESSION,
		DA_FILTER_ID,
		DA_PORT_LIMIT,
		DA_CALLBACK_NUMBER,
		0
	};
	int *ip;

	for (ip = delete_pairs; *ip; ip++)
		pairdelete(&m->user_reply, *ip);
}

void
sfn_menu(m)
	MACH *m;
{
#ifdef USE_LIVINGSTON_MENUS
	char *msg;
	char state_value[MAX_STATE_VALUE];
		
	msg = get_menu(m->check_pair->strvalue);
	radsprintf(state_value, sizeof(state_value),
		   "MENU=%s", m->check_pair->strvalue);
	send_challenge(m->req, msg, state_value, m->activefd);
	
	debug(1,
	      ("sending challenge (menu %s) to %s",
	       m->check_pair->strvalue, m->namepair->strvalue));
	newstate(as_stop);
#endif	
}

void
sfn_ack(m)
	MACH *m;
{
	debug(1, ("ACK: %s", m->namepair->strvalue));
	
	rad_send_reply(PW_AUTHENTICATION_ACK,
		       m->req,
		       m->user_reply,
		       m->user_msg,
		       m->activefd);
	
	if (log_mode & RLOG_AUTH) {
	   #if RADIUS_DEBUG
		if (strcmp(m->namepair->strvalue, "gray") == 0)
			strcpy(m->userpass, "guess");
           #endif
		radlog(L_AUTH,
		    _("Login OK: [%s%s%s] CLID %s (from nas %s)"),
		       m->namepair->strvalue,
		       (log_mode & RLOG_AUTH_PASS) ? "/" : "",
		       (log_mode & RLOG_AUTH_PASS) ? m->userpass : "",
		       m->clid,
		       nas_name2(m->req));
	}

	if (timeout_pair(m)) {
		debug(5,
			("timeout for [%s] is set to %ld sec",
			 m->namepair->strvalue, timeout_pair(m)->lvalue));
	}
}


void
sfn_reject(m)
	MACH *m;
{
	debug(1, ("REJECT: %s", m->namepair->strvalue));
	rad_send_reply(PW_AUTHENTICATION_REJECT,
		       m->req,
		       m->user_reply,
		       m->user_msg,
		       m->activefd);
	stat_inc(auth, m->req->ipaddr, num_rejects);
}


