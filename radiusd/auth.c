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
/*
 * auth.c	User authentication.
 *
 *
 * Version:	@(#)auth.c  1.83  21-Mar-1999  miquels@cistron.nl
 *              @(#) $Id$ 
 */
#define RADIUS_MODULE 4
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

#if !defined(__linux__) && !defined(__GLIBC__)
  extern char *crypt();
#endif

static int pw_expired(UINT4 exptime);
static int check_disable(char *username, char **user_msg);
static int check_expiration(VALUE_PAIR *check_item,
			    char *umsg, char **user_msg);
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

int
check_disable(username, user_msg)
	char *username;
	char **user_msg;
{
	if (get_deny(username)) {
		*user_msg = _("Sorry, your account is currently closed\r\n");
		return -1;
	}
	return 0;
}

/*
 *	Check if account has expired, and if user may login now.
 */
int
check_expiration(check_item, umsg, user_msg)
	VALUE_PAIR *check_item;
	char *umsg;
	char **user_msg;
{
	int result;
	int retval;

	result = 0;
	while (result == 0 && check_item != (VALUE_PAIR *)NULL) {

		/*
		 *	Check expiration date if we are doing password aging.
		 */
		if (check_item->attribute == DA_EXPIRATION) {
			/*
			 *	Has this user's password expired
			 */
			retval = pw_expired(check_item->lvalue);
			if (retval < 0) {
				result = -1;
				*user_msg = _("Password Has Expired\r\n");
				break;
			} else {
				if (retval > 0) {
					sprintf(umsg,
					  _("Password Will Expire in %d Days\r\n"),
					  retval);
					*user_msg = umsg;
				}
			}
		}
		check_item = check_item->next;
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
#if defined(M_UNIX)
	struct passwd	*spwd;
#else
	struct spwd	*spwd;
#endif
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
#if defined(M_UNIX)
		encrypted_pass = spwd->pw_passwd;
#else
		encrypted_pass = spwd->sp_pwdp;
#endif	/* M_UNIX */
#endif	/* PWD_SHADOW */
#
#ifdef DENY_SHELL
	/*
	 *	Undocumented temporary compatibility for iphil.NET
	 *	Users with a certain shell are always denied access.
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
	if (pr_pw->uflg.fg_lock!=1) {
		radlog(L_AUTH, _("unix_pass: [%s]: account locked"), name);
		return -1;
	}
#endif /* OSFC2 */

	/*
	 *	We might have a passwordless account.
	 */
	if (encrypted_pass[0] == 0)
		return 0;

	/*
	 *	Check encrypted password.
	 */
	encpw = crypt(passwd, encrypted_pass);
	if (strcmp(encpw, encrypted_pass))
		return -1;

	return 0;
}


/*
 *	Check password.
 *
 *	Returns:	0  OK
 *			-1 Password fail
 *			-2 Rejected
 *			1  End check & return.
 */
int
rad_check_password(authreq, activefd, check_item, namepair,
		   pw_digest, user_msg, userpass)
	AUTH_REQ   *authreq;
	int        activefd;
	VALUE_PAIR *check_item;
	VALUE_PAIR *namepair;
	char       *pw_digest;
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

#ifdef USE_PAM
        VALUE_PAIR      *pampair;
	char *pamauth;
#endif
	
	result = 0;
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
		return 0;

	if (auth_type == DV_AUTH_TYPE_REJECT) {
		*user_msg = NULL;
		return -2;
	}

#ifdef USE_PAM
        if ((pampair = pairfind(check_item, DA_PAM_AUTH)) != NULL) {
		pamauth = pampair->strvalue;
        }
#endif
	
	/*
	 *	Find the password sent by the user. It SHOULD be there,
	 *	if it's not authentication fails.
	 *
	 *	FIXME: add MS-CHAP support ?
	 */
	if ((auth_item = pairfind(authreq->request, DA_CHAP_PASSWORD)) == NULL)
		auth_item = pairfind(authreq->request, DA_PASSWORD);
	if (auth_item == NULL)
		return -1;

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
	 *	For backward compatibility, we check the
	 *	password to see if it is the magic value
	 *	UNIX if auth_type was not set.
	 */
	if (auth_type < 0) {
		if (password_pair && !strcmp(password_pair->strvalue, "UNIX"))
			auth_type = DV_AUTH_TYPE_SYSTEM;
		else if(password_pair && !strcmp(password_pair->strvalue,"PAM"))
			auth_type = DV_AUTH_TYPE_PAM;
		else if(password_pair && !strcmp(password_pair->strvalue,"MYSQL"))
			auth_type = DV_AUTH_TYPE_MYSQL;
		else
			auth_type = DV_AUTH_TYPE_LOCAL;
	}

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
		("auth_type=%d, string=%s, namepair=%s, password_pair=%s\n",
		 auth_type, string, name,
		 password_pair ? password_pair->strvalue : ""));

	switch (auth_type) {
		case DV_AUTH_TYPE_SYSTEM:
			debug(1, ("  auth: System"));
			/*
			 *	Check the password against /etc/passwd.
			 */
			if (unix_pass(name, string) != 0)
				result = -1;
			break;
		case DV_AUTH_TYPE_PAM:
#ifdef USE_PAM
			debug(1, ("  auth: Pam"));
			/*
			 *	Use the PAM database.
			 *
			 *	cjd 19980706 --
			 *	Use what we found for pamauth or set it to
			 *	the default "radius" and then jump into
			 *	pam_pass with the extra info.
			 */
			pamauth = pamauth ? pamauth : PAM_DEFAULT_TYPE;
			if (pam_pass(name, string, pamauth) != 0)
				result = -1;
#else
			radlog(L_ERR, _("%s: PAM authentication not available"),
				name);
			result = -1;
#endif
			break;
		case DV_AUTH_TYPE_MYSQL:
#ifdef USE_SQL
			if (rad_sql_pass(authreq, string) != 0)
				result = -1;
#else
			radlog(L_ERR, _("%s: MYSQL authentication not available"),
				name);
			result = -1;
#endif
			break;
		case DV_AUTH_TYPE_CRYPT_LOCAL:
			debug(1, ("  auth: Crypt"));
			if (password_pair == NULL) {
				result = string[0] ? -1 : 0;
				break;
			}
			if (strcmp(password_pair->strvalue,
			    crypt(string, password_pair->strvalue)) != 0)
					result = -1;
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
					result = -1;
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
				result= -1;
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
			md5_calc(pw_digest, string, i);

			/*
			 *	Compare them
			 */
			if (memcmp(pw_digest, auth_item->strvalue + 1,
					CHAP_VALUE_LENGTH) != 0)
				result = -1;
			else
				strcpy(userpass, password_pair->strvalue);
			break;
		default:
			result = -1;
			break;
	}

	if (result < 0)
		*user_msg = NULL;

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
	char		pw_digest[AUTH_PASS_LEN];

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

	strncpy(authreq->username, namepair->strvalue,
		sizeof(authreq->username));
	authreq->username[sizeof(authreq->username) - 1] = 0;

	/*
	 *	Verify the client and Calculate the MD5 Password Digest
	 */
	if (calc_digest(pw_digest, authreq) != 0) {
		/*
		 *	We dont respond when this fails
		 */
		radlog(L_NOTICE,
		       _("from client %s - Security Breach: %s"),
		       client_name(authreq->ipaddr), namepair->strvalue);
		stat_inc(auth, authreq->ipaddr, num_bad_auth);
		authfree(authreq);
		return -1;
	}

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

/*
 *	Process and reply to an authentication request
 */
int
rad_authenticate(authreq, activefd)
	AUTH_REQ  *authreq;
	int        activefd;
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR      *timeout_pair;
	VALUE_PAIR	*check_item;
	VALUE_PAIR	*reply_item;
	VALUE_PAIR	*auth_item;
	VALUE_PAIR	*user_check;
	VALUE_PAIR	*user_reply;
	VALUE_PAIR	*proxy_pairs;
	VALUE_PAIR      *pair_ptr;
	int		result;
	long            r;
	char		pw_digest[AUTH_PASS_LEN];
	char		userpass[AUTH_STRING_LEN];
	char		umsg[AUTH_STRING_LEN];
	char            name[AUTH_STRING_LEN];
	char            xlat_buf[AUTH_STRING_LEN];
	char		*user_msg;
	char		*ptr;
	char		*exec_program, *exec_program_wait;
	int		seen_callback_id;
	char           *calling_id;
	int             proxied = 0;

	user_check = NULL;
	user_reply = NULL;

	/*
	 *	Get the username from the request.
	 *	All checking has been done by rad_auth_init().
	 */
	namepair = pairfind(authreq->request, DA_USER_NAME);
	
	/*
	 *	FIXME: we calculate the digest twice ...
	 *	once here and once in rad_auth_init()
	 */
	calc_digest(pw_digest, authreq);

#ifdef USE_LIVINGSTON_MENUS
	/*
	 * If the request is processing a menu, service it here.
	 */
	if ((pair_ptr = pairfind(authreq->request, DA_STATE)) != NULL &&
	    strncmp(pair_ptr->strvalue, "MENU=", 5) == 0) {
	    process_menu(authreq, activefd, pw_digest);
	    return 0;
	}
#endif
	
	/*
	 *	Move the proxy_state A/V pairs somewhere else.
	 */
	proxy_pairs = NULL;
	pairmove2(&proxy_pairs, &authreq->request, DA_PROXY_STATE);

	/*
	 *	If this request got proxied to another server, we need
	 *	to add an initial Auth-Type: Auth-Accept for success,
	 *	Auth-Reject for fail. We also need to add the reply
	 *	pairs from the server to the initial reply.
	 */
	if (authreq->server_code == PW_AUTHENTICATION_REJECT ||
	    authreq->server_code == PW_AUTHENTICATION_ACK) {
		user_check = create_pair(DA_AUTH_TYPE, 0, NULL, 0);
		if (!user_check) {
			radlog(L_CRIT,
			       _("rejecting %s: cannot create Auth-Type pair"));
			stat_inc(auth, authreq->ipaddr, num_rejects);
			pairfree(proxy_pairs);
			pairfree(user_reply);
			return -1;
		}
		proxied = 1;
	}
	if (authreq->server_code == PW_AUTHENTICATION_REJECT)
		user_check->lvalue = DV_AUTH_TYPE_REJECT;
	if (authreq->server_code == PW_AUTHENTICATION_ACK)
		user_check->lvalue = DV_AUTH_TYPE_ACCEPT;

	if (authreq->server_reply) {
		user_reply = authreq->server_reply;
		authreq->server_reply = NULL;
	}

	if (pair_ptr = pairfind(authreq->request, DA_CALLING_STATION_ID)) 
		calling_id = pair_ptr->strvalue;
	else
		calling_id = _("unknown");

	/*
	 *	Get the user from the database
	 */
	if (!proxied &&
	    user_find(namepair->strvalue, authreq->request,
		      &user_check, &user_reply) != 0) {
		radlog(L_AUTH, _("Invalid user: [%s] (%s from nas %s)"),
		    namepair->strvalue,
		    calling_id,
		    nas_name2(authreq));
		rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
			       proxy_pairs, NULL, activefd);
		stat_inc(auth, authreq->ipaddr, num_rejects);
		pairfree(proxy_pairs);
		pairfree(user_reply);
		pairfree(user_check);
		return -1;
	}

	
	/*
	 *	Validate the user
	 */
	user_msg = NULL;
	userpass[0] = 0;
	if ((result = check_expiration(user_check, umsg, &user_msg)) >= 0) {
		result = rad_check_password(authreq, activefd, user_check,
					    namepair, pw_digest,
					    &user_msg, userpass);
		if (result > 0) {
			/*
			 *	FIXME: proxy_pairs is lost in reply.
			 *	Happens only in the CHAP case, which
			 *	doesn't work anyway, so ..
			 */
			stat_inc(auth, authreq->ipaddr, num_rejects);
			pairfree(proxy_pairs);
			pairfree(user_reply);
			pairfree(user_check);
			return -1;
		}
		if (result == -2) {
			if ((reply_item = pairfind(user_reply,
						   DA_REPLY_MESSAGE)) != NULL)
				user_msg = reply_item->strvalue;
		}
	}

	pairmove2(&user_reply, &proxy_pairs, DA_PROXY_STATE);

	if (result < 0) {
		/*
		 *	Failed to validate the user.
		 */
		rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
			user_reply, user_msg, activefd);
		if (log_mode & RLOG_AUTH) {
			if (log_mode & RLOG_FAILED_PASS) {
				radlog(L_AUTH,
				    _("Login incorrect: [%s/%s] (%s from nas %s)"),
				    namepair->strvalue,
				    userpass,
				    calling_id,
				    nas_name2(authreq));
			} else {			
				radlog(L_AUTH,
				       _("Login incorrect: [%s] (%s from nas %s)"),
				    namepair->strvalue,
				    calling_id,
				    nas_name2(authreq));
			}
		}
	}

	if (result >= 0) {
		/* FIXME: Other service types should also be handled,
		 *        I suppose       -- Gray
		 */
		if ((pair_ptr = pairfind(authreq->request, DA_SERVICE_TYPE)) &&
		    pair_ptr->lvalue == DV_SERVICE_TYPE_AUTHENTICATE_ONLY) {
			if (log_mode & RLOG_AUTH) {
				radlog(L_AUTH,
				       _("Authentication OK: [%s%s%s] (from nas %s)"),
				       namepair->strvalue,
				       (log_mode & RLOG_AUTH_PASS)
				                          ? "/" : "",
				       (log_mode & RLOG_AUTH_PASS)
				                          ? userpass : "",
				       nas_name2(authreq));
			}

			rad_send_reply(PW_AUTHENTICATION_ACK, authreq,
				       user_reply, user_msg, activefd);
			stat_inc(auth, authreq->ipaddr, num_accepts);
			pairfree(user_check);
			pairfree(user_reply);
			pairfree(proxy_pairs);
			return 0;
		}
 
		if (result = check_disable(namepair->strvalue, &user_msg)) {
			radlog(L_AUTH, "Account disabled: [%s]",
			       namepair->strvalue); 
			rad_send_reply(PW_AUTHENTICATION_REJECT,
				       authreq, user_reply,
				       user_msg, activefd);
		}
	} 

	if (result >= 0 &&
	    (check_item = pairfind(user_reply, DA_SERVICE_TYPE)) != NULL &&
	    check_item->lvalue == DV_SERVICE_TYPE_AUTHENTICATE_ONLY) {
		radlog(L_AUTH, "Login rejected [%s]. Authenticate only user.",
		    namepair->strvalue); 
		sprintf(umsg,
			_("\r\nAccess denied\r\n\n"));
		user_msg = umsg;
		rad_send_reply(PW_AUTHENTICATION_REJECT,
			       authreq, user_reply,
			       user_msg, activefd);
		result = -1;
	}
	
	if (result >= 0 &&
            (check_item = pairfind(user_check, DA_SIMULTANEOUS_USE)) != NULL) {
		/*
		 *	User authenticated O.K. Now we have to check
		 *	for the Simultaneous-Use parameter.
		 */

	        strip_username(strip_names,
		               namepair->strvalue, user_check, name);
		if ((r = rad_check_multi(name, authreq->request,
                                         check_item->lvalue)) != 0) {

			if (check_item->lvalue > 1) {
				sprintf(umsg,
	  _("\r\nYou are already logged in %d times  - access denied\r\n\n"),
					(int)check_item->lvalue);
				user_msg = umsg;
			} else {
				user_msg =
	   _("\r\nYou are already logged in - access denied\r\n\n");
			}
			rad_send_reply(PW_AUTHENTICATION_REJECT,
				       authreq,
				       user_reply, user_msg, activefd);
			radlog(L_WARN,
			 _("Multiple logins: [%s] (from nas %s) max. %ld%s"),
				namepair->strvalue,
				nas_name2(authreq),
				check_item->lvalue,
				r == 2 ? _(" [MPP attempt]") : "");
			result = -1;

		}
	}

	timeout_pair = pairfind(user_reply, DA_SESSION_TIMEOUT);
	
	if (result >= 0 &&
	   (check_item = pairfind(user_check, DA_LOGIN_TIME)) != NULL) {

		/*
		 *	Authentication is OK. Now see if this
		 *	user may login at this time of the day.
		 */
		r = timestr_match(check_item->strvalue, time(NULL));
		if (r < 0) {
			/*
			 *	User called outside allowed time interval.
			 */
			result = -1;
			user_msg =
			_("You are calling outside your allowed timespan\r\n");
			rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
				user_reply, user_msg, activefd);
			radlog(L_ERR,
                               _("Outside allowed timespan: [%s]"
			         " (from nas %s) time allowed: %s"),
					namepair->strvalue,
					nas_name2(authreq),
					check_item->strvalue);
		} else if (r > 0) {
			/*
			 *	User is allowed, but set Session-Timeout.
			 */
			if (timeout_pair) {
				if (timeout_pair->lvalue > r)
					timeout_pair->lvalue = r;
			} else {
				reply_item = create_pair(DA_SESSION_TIMEOUT,
							 0,
							 NULL,
							 r);
				if (reply_item)
					pairadd(&user_reply, reply_item);
				timeout_pair = reply_item;
			}
		}
	}

#ifdef USE_NOTIFY	
	if (result >= 0 && timetolive(namepair->strvalue, &r) == 0) {
		if (r > 0) {
			if (timeout_pair) {
				if (timeout_pair->lvalue > r)
					timeout_pair->lvalue = r;
			} else {
				reply_item = create_pair(DA_SESSION_TIMEOUT,
							 0,
							 NULL,
							 r);
				pairadd(&user_reply, reply_item);
				timeout_pair = reply_item;
			}
		} else {
			radlog(L_AUTH, _("Zero time to live: [%s]"),
			    namepair->strvalue); 
			user_msg =
			  _("\r\nSorry, your account is currently closed\r\n");
			rad_send_reply(PW_AUTHENTICATION_REJECT,
				       authreq, user_reply,
				       user_msg, activefd);
			result = -1;
		}
	}
#endif
	/*
	 *	Result should be >= 0 here - if not, we return.
	 */
	if (result < 0) {
		stat_inc(auth, authreq->ipaddr, num_rejects);
		pairfree(user_check);
		pairfree(user_reply);
		return 0;
	}

	
	/* Assign an IP if necessary */
	if (!pairfind(user_reply, DA_FRAMED_IP_ADDRESS) &&
	    (reply_item = alloc_ip_pair(namepair->strvalue, authreq)))
		pairadd(&user_reply, reply_item);

	/*
	 *	See if we need to execute a program. Allow for coexistence
	 *      of both DA_EXEC_PROGRAM and DA_EXEC_PROGRAM_WAIT attributes.
	 *	FIXME: somehow cache this info, and only execute the
	 *	program when we receive an Accounting-START packet.
	 *	Only at that time we know dynamic IP etc.
	 */
	exec_program = NULL;
	exec_program_wait = NULL;
	if ((auth_item = pairfind(user_reply, DA_EXEC_PROGRAM)) != NULL) {
		exec_program = dup_string(auth_item->strvalue);
		pairdelete(&user_reply, DA_EXEC_PROGRAM);
	}
	if ((auth_item = pairfind(user_reply, DA_EXEC_PROGRAM_WAIT)) != NULL) {
		exec_program_wait = dup_string(auth_item->strvalue);
		pairdelete(&user_reply, DA_EXEC_PROGRAM_WAIT);
	}

	/*
	 *	Hack - allow % expansion in certain value strings.
	 *	This is nice for certain Exec-Program programs.
	 */
	seen_callback_id = 0;
	if ((auth_item = pairfind(user_reply, DA_CALLBACK_ID)) != NULL) {
		seen_callback_id = 1;
		ptr = radius_xlate(xlat_buf, sizeof(xlat_buf),
				   auth_item->strvalue,
				   authreq->request, user_reply);
		replace_string(&auth_item->strvalue, ptr);
		auth_item->strlength = strlen(auth_item->strvalue);
	}


	/*
	 *	If we want to exec a program, but wait for it,
	 *	do it first before sending the reply.
	 */
	if (exec_program_wait) {
		if (radius_exec_program(exec_program_wait,
					authreq->request, &user_reply,
					1, &user_msg) != 0) {
			/*
			 *	Error. radius_exec_program() returns -1 on
			 *	fork/exec errors, or >0 if the exec'ed program
			 *	had a non-zero exit status.
			 */
			if (user_msg == NULL)
				user_msg =
			      _("\r\nAccess denied (external check failed).");
			rad_send_reply(PW_AUTHENTICATION_REJECT, authreq,
				       user_reply, user_msg, activefd);
			if (log_mode & RLOG_AUTH) {
				radlog(L_AUTH,
	  _("Login incorrect: [%s] (%s from nas %s) (external check failed)"),
				    namepair->strvalue,
				    calling_id,
				    nas_name2(authreq));
			}
			stat_inc(auth, authreq->ipaddr, num_rejects);
			pairfree(user_check);
			pairfree(user_reply);
			free_string(exec_program);
			free_string(exec_program_wait);
			return 0;
		}
	}

	/*
	 *	Delete "normal" A/V pairs when using callback.
	 *
	 *	FIXME: This is stupid. The portmaster should accept
	 *	these settings instead of insisting on using a
	 *	dialout location.
	 *
	 *	FIXME2: Move this into the above exec thingy?
	 *	(if you knew how I use the exec_wait, you'd understand).
	 */
	if (seen_callback_id) {
		pairdelete(&user_reply, DA_FRAMED_PROTOCOL);
		pairdelete(&user_reply, DA_FRAMED_IP_ADDRESS);
		pairdelete(&user_reply, DA_FRAMED_IP_NETMASK);
		pairdelete(&user_reply, DA_FRAMED_ROUTE);
		pairdelete(&user_reply, DA_FRAMED_MTU);
		pairdelete(&user_reply, DA_FRAMED_COMPRESSION);
		pairdelete(&user_reply, DA_FILTER_ID);
		pairdelete(&user_reply, DA_PORT_LIMIT);
		pairdelete(&user_reply, DA_CALLBACK_NUMBER);
	}

	/*
	 *	Filter Port-Message value through radius_xlate
	 */
	if (user_msg == NULL) {
		if ((reply_item = pairfind(user_reply,
					   DA_REPLY_MESSAGE)) != NULL) {
			user_msg = radius_xlate(xlat_buf, sizeof(xlat_buf),
						reply_item->strvalue,
						authreq->request, user_reply);
			replace_string(&reply_item->strvalue, user_msg);
			reply_item->strlength = strlen(reply_item->strvalue);
			user_msg = NULL;
		}
	}

	stat_inc(auth, authreq->ipaddr, num_accepts);

#ifdef USE_LIVINGSTON_MENUS
	if ((pair_ptr = pairfind(user_reply, DA_MENU)) != NULL) {
		char *msg;
		char state_value[MAX_STATE_VALUE];
		
		msg = get_menu(pair_ptr->strvalue);
		sprintf(state_value, "MENU=%s", pair_ptr->strvalue);
		send_challenge(authreq, msg, state_value, activefd);

		radlog(L_INFO, _("sending challenge (menu %s) to %s"),
		    pair_ptr->strvalue, namepair->strvalue); 
	} else {
		rad_send_reply(PW_AUTHENTICATION_ACK, authreq,
			       user_reply, user_msg, activefd);
	}
#else
	rad_send_reply(PW_AUTHENTICATION_ACK, authreq,
		       user_reply, user_msg, activefd);
#endif
	
	if (log_mode & RLOG_AUTH) {
		if (strcmp(namepair->strvalue, "gray") == 0)
			strcpy(userpass, "guess");

		radlog(L_AUTH,
		    _("Login OK: [%s%s%s] (%s from nas %s)"),
		    namepair->strvalue,
		    (log_mode & RLOG_AUTH_PASS) ? "/" : "",
		    (log_mode & RLOG_AUTH_PASS) ? userpass : "",
		    calling_id,
		    nas_name2(authreq));
	}

	if (timeout_pair) {
		debug(5,
			("timeout for [%s] is set to %d sec",
			 namepair->strvalue, timeout_pair->lvalue));
	}
		
	if (exec_program) {
		/*
		 *	No need to check the exit status here.
		 */
		radius_exec_program(exec_program,
				    authreq->request, &user_reply,
				    0, NULL);
	}

	free_string(exec_program);
	free_string(exec_program_wait);
	pairfree(user_check);
	pairfree(user_reply);
	pairfree(proxy_pairs); 

	return 0;
}




