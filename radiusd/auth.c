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

#define RADIUS_MODULE_AUTH_C
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
#include <ctype.h>
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
#include <rewrite.h>
#if defined(USE_SQL)
# include <radsql.h>
#endif
#include <timestr.h>
#include <envar.h>
#include <obstack1.h>

#if !defined(__linux__) && !defined(__GLIBC__)
  extern char *crypt();
#endif

static int pw_expired(UINT4 exptime);
static int unix_pass(char *name, char *passwd);
static int rad_check_password(RADIUS_REQ *radreq, 
                              VALUE_PAIR *check_item, VALUE_PAIR *namepair,
                              char **user_msg,
                              char *userpass);

/*
 * Tests to see if the users password has expired.
 *
 * Return: Number of days before expiration if a warning is required
 *         otherwise 0 for success and -1 for failure.
 */
static int
pw_expired(exptime)
        UINT4 exptime;
{
        struct timeval  tp;
        struct timezone tzp;
        UINT4           exp_remain;
        int             exp_remain_int;

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

char *username_valid_chars;

/*
 * Check if the username is valid. Valid usernames consist of 
 * alphanumeric characters and symbols from username_valid_chars[]
 * array
 */
int
check_user_name(p)
        char *p;
{
        for (; *p && (isalnum(*p) || strchr(username_valid_chars, *p)); p++)
                ;
        return *p;
}

static pthread_mutex_t pwd_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Check the users password against UNIX password database.
 */
int
unix_pass(name, passwd)
        char *name;
        char *passwd;
{
        int rc;
        struct passwd *pwd;
        char *encpw;
        int pwlen;
        char *encrypted_pass = NULL;

#if defined(PWD_SHADOW)
# if defined(M_UNIX)
        struct passwd *spwd;
# else
        struct spwd *spwd;
# endif
#endif /* PWD_SHADOW */
#ifdef OSFC2
        struct pr_passwd *pr_pw;
#endif
	
	pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock,
			     &pwd_mutex);
        pthread_mutex_lock(&pwd_mutex);

#if defined(OSFC2)
        if (pr_pw = getprpwnam(name))
                encrypted_pass = pr_pw->ufld.fd_encrypt;
#elif defined(PWD_SHADOW)
        /* See if there is a shadow password. */
        if (spwd = getspnam(name))
# if defined(M_UNIX)
                encrypted_pass = spwd->pw_passwd;
# else
       	        encrypted_pass = spwd->sp_pwdp;
# endif /* M_UNIX */
#else /* !OSFC2 && !PWD_SHADOW */
        /* Get encrypted password from password file */
        if (pwd = getpwnam(name)) 
		encrypted_pass = pwd->pw_passwd;
#endif /* OSFC2 */

	if (encrypted_pass) {
#if defined(PWD_SHADOW) && !defined(M_UNIX)
		/* Check if password has expired. */
		if (spwd
		    && spwd->sp_expire > 0
		    && (time(NULL) / SECONDS_PER_DAY) > spwd->sp_expire) {
			radlog(L_NOTICE,
			       "unix_pass: [%s]: %s",
			       name, _("password has expired"));
			encrypted_pass = NULL;
		}
#endif

#ifdef OSFC2
		/* Check if the account is locked. */
		if (pr_pw->uflg.fg_lock != 1) {
			radlog(L_NOTICE,
			       "unix_pass: [%s]: %s",
			       name, _("account locked"));
			encrypted_pass = NULL;
		}
#endif /* OSFC2 */
	}

	if (encrypted_pass) {
		if (encrypted_pass[0] == 0)
			encrypted_pass = NULL;
		else
			encrypted_pass = estrdup(encrypted_pass);
	}
	pthread_cleanup_pop(1);

        if (!encrypted_pass)
                return -1;

        /*
         * Check encrypted password.
         */
        pwlen = strlen(encrypted_pass)+1;
        encpw = emalloc(pwlen);
        rc = md5crypt(passwd, encrypted_pass, encpw, pwlen) == NULL
                || strcmp(encpw, encrypted_pass);
        efree(encpw);
	efree(encrypted_pass);
        if (rc)
                return -1;

        return 0;
}


/*
 *      Check password.
 *
 *      Returns:        AUTH_OK      OK
 *                      AUTH_FAIL    Password fail
 *                      AUTH_NOUSER  No such user 
 *                      AUTH_REJECT  Rejected
 *                      AUTH_IGNORE  Silently ignored                 
 */
int
rad_check_password(radreq, check_item, namepair, user_msg, userpass)
        RADIUS_REQ   *radreq;
        VALUE_PAIR *check_item;
        VALUE_PAIR *namepair;
        char       **user_msg;
        char       *userpass;
{
        char *ptr;
        char *real_password = NULL;
        char name[AUTH_STRING_LEN];
        VALUE_PAIR *auth_item;
        VALUE_PAIR *tmp;
        int auth_type = -1;
        int length;
        int result;
        char *authdata = NULL;
        char pw_digest[AUTH_VECTOR_LEN];
        int pwlen;
        char *pwbuf;
        char *challenge;
	int challenge_len;
	
        result = AUTH_OK;
        userpass[0] = 0;

        /* Process immediate authentication types */
        if ((tmp = avl_find(check_item, DA_AUTH_TYPE)) != NULL)
                auth_type = tmp->lvalue;

	switch (auth_type) {
	case DV_AUTH_TYPE_ACCEPT:
                return AUTH_OK;

	case DV_AUTH_TYPE_REJECT:
                return AUTH_REJECT;

	case DV_AUTH_TYPE_IGNORE:
		return AUTH_IGNORE;
	}

        /* Find the password sent by the user. If it's not present,
           authentication fails. */
        
        if (auth_item = avl_find(radreq->request, DA_CHAP_PASSWORD))
                auth_type = DV_AUTH_TYPE_LOCAL;
        else
                auth_item = avl_find(radreq->request, DA_USER_PASSWORD);
        
        /* Decrypt the password. */
        if (auth_item) {
                if (auth_item->strlength == 0)
                        userpass[0] = 0;
                else
                        req_decrypt_password(userpass, radreq,
                                             auth_item);
        } else /* if (auth_item == NULL) */
                return AUTH_FAIL;
        
        /* Set up authentication data */
        if ((tmp = avl_find(check_item, DA_AUTH_DATA)) != NULL) 
                authdata = tmp->strvalue;

        /* Find the 'real' password */
        tmp = avl_find(check_item, DA_USER_PASSWORD);
        if (tmp)
                real_password = estrdup(tmp->strvalue);
        else if (tmp = avl_find(check_item, DA_PASSWORD_LOCATION)) {
                switch (tmp->lvalue) {
                case DV_PASSWORD_LOCATION_SQL:
#ifdef USE_SQL
                        real_password = rad_sql_pass(radreq, authdata);
                        if (!real_password)
                                return AUTH_NOUSER;
#else
                        radlog_req(L_ERR, radreq,
                                   _("SQL authentication not available"));
                        return AUTH_NOUSER;
#endif
                        break;
                /*NOTE: add any new location types here */
                default:
                        radlog(L_ERR,
                               _("unknown Password-Location value: %ld"),
                               tmp->lvalue);
                        return AUTH_FAIL;
                }
        }

        /* Process any prefixes/suffixes. */
        strip_username(1, namepair->strvalue, check_item, name);

        debug(1,
                ("auth_type=%d, userpass=%s, name=%s, password=%s",
                 auth_type, userpass, name,
                 real_password ? real_password : "NONE"));

        switch (auth_type) {
        case DV_AUTH_TYPE_SYSTEM:
                debug(1, ("  auth: System"));
                if (unix_pass(name, userpass) != 0)
                        result = AUTH_FAIL;
                break;
		
        case DV_AUTH_TYPE_PAM:
#ifdef USE_PAM
                debug(1, ("  auth: Pam"));
                /* Provide defaults for authdata */
                if (authdata == NULL &&
                    (tmp = avl_find(check_item, DA_PAM_AUTH)) != NULL) {
                        authdata = tmp->strvalue;
                }
                authdata = authdata ? authdata : PAM_DEFAULT_TYPE;
                if (pam_pass(name, userpass, authdata, user_msg) != 0)
                        result = AUTH_FAIL;
#else
                radlog_req(L_ERR, radreq,
                           _("PAM authentication not available"));
                result = AUTH_NOUSER;
#endif
                break;

        case DV_AUTH_TYPE_CRYPT_LOCAL:
                debug(1, ("  auth: Crypt"));
                if (real_password == NULL) {
                        result = AUTH_FAIL;
                        break;
                }
                pwlen = strlen(real_password)+1;
                pwbuf = emalloc(pwlen);
                if (!md5crypt(userpass, real_password, pwbuf, pwlen))
                        result = AUTH_FAIL;
                else if (strcmp(real_password, pwbuf) != 0)
                        result = AUTH_FAIL;
                debug(1,("pwbuf: %s", pwbuf));
                efree(pwbuf);
                break;
                
        case DV_AUTH_TYPE_LOCAL:
                debug(1, ("  auth: Local"));
                /* Local password is just plain text. */
                if (auth_item->attribute != DA_CHAP_PASSWORD) {
                        if (real_password == NULL ||
                            strcmp(real_password, userpass) != 0)
                                result = AUTH_FAIL;
                        break;
                }

                /* CHAP: RFC 2865, page 7
		   The RADIUS server looks up a password based on the
		   User-Name, encrypts the challenge using MD5 on the
		   CHAP ID octet, that password, and the CHAP challenge 
		   (from the CHAP-Challenge attribute if present,
		   otherwise from the Request Authenticator), and compares
		   that result to the CHAP-Password.  If they match, the
		   server sends back an Access-Accept, otherwise it sends
		   back an Access-Reject. */

		/* Provide some userpass in case authentication fails */
                strcpy(userpass, "{chap-password}");
		
                if (real_password == NULL) {
                        result = AUTH_FAIL;
                        break;
                }

		/* Compute the length of the password buffer and
		   allocate it */
                length = strlen(real_password);
		
                if (tmp = avl_find(radreq->request, DA_CHAP_CHALLENGE)) {
                        challenge = tmp->strvalue;
                        challenge_len = tmp->strlength;
                } else {
                        challenge = radreq->vector;
                        challenge_len = AUTH_VECTOR_LEN;
                }

                pwlen = 1 + length + challenge_len;
		pwbuf = emalloc(pwlen);
		
                ptr = pwbuf;
                *ptr++ = *auth_item->strvalue;
                memcpy(ptr, real_password, length);
                ptr += length;
                memcpy(ptr, challenge, challenge_len);

		/* Compute the MD5 hash */
                md5_calc(pw_digest, (u_char*) pwbuf, pwlen);
                efree(pwbuf);
		
                /* Compare them */
                if (memcmp(pw_digest, auth_item->strvalue + 1,
			   CHAP_VALUE_LENGTH) != 0)
                        result = AUTH_FAIL;
                else
                        strcpy(userpass, real_password);
                break;
		
        default:
                result = AUTH_FAIL;
                break;
        }

        if (real_password) {
                /* just in case: */
                memset(real_password, 0, strlen(real_password)); 
                efree(real_password);
        }
        return result;
}

/*
 *      Initial step of authentication.
 *      Find username, calculate MD5 digest, and
 *      process the hints and huntgroups file.
 */
int
rad_auth_init(radreq, activefd)
        RADIUS_REQ *radreq;
        int       activefd;
{
        VALUE_PAIR *namepair;
        
        /*
         * Get the username from the request
         */
        namepair = avl_find(radreq->request, DA_USER_NAME);

        if ((namepair == (VALUE_PAIR *)NULL) || 
           (strlen(namepair->strvalue) <= 0)) {
                radlog_req(L_ERR, radreq, _("No username"));
                stat_inc(auth, radreq->ipaddr, num_bad_req);
                return -1;
        }
        debug(1,("checking username: %s", namepair->strvalue));
        if (check_user_name(namepair->strvalue)) {
                radlog_req(L_ERR, radreq, _("Malformed username"));
                stat_inc(auth, radreq->ipaddr, num_bad_req);
                return -1;
        }
                
        /*
         * Add any specific attributes for this username.
         */
        hints_setup(radreq);

        if (auth_detail)
                write_detail(radreq, -1, "detail.auth");

        /*
         * See if the user has access to this huntgroup.
         */
        if (!huntgroup_access(radreq)) {
                radlog_req(L_NOTICE, radreq, _("No huntgroup access"));
                rad_send_reply(RT_AUTHENTICATION_REJECT, radreq,
                               radreq->request, NULL, activefd);
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
        as_eval,
        as_scheme,
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
        RADIUS_REQ *req;
        VALUE_PAIR *user_check;
        VALUE_PAIR *user_reply;
        int        activefd;
        
        VALUE_PAIR *namepair;
        VALUE_PAIR *check_pair;
        VALUE_PAIR *timeout_pair;
        char       userpass[AUTH_STRING_LEN+1];

        char       *user_msg;
        struct obstack msg_stack;
        
        char       *clid;
        enum auth_state state;
} AUTH_MACH;

static void sfn_init(AUTH_MACH*);
static void sfn_validate(AUTH_MACH*);
static void sfn_eval_reply(AUTH_MACH*);
static void sfn_scheme(AUTH_MACH*);
static void sfn_service(AUTH_MACH*);
static void sfn_disable(AUTH_MACH*);
static void sfn_service_type(AUTH_MACH*);
static void sfn_realmuse(AUTH_MACH*);
static void sfn_simuse(AUTH_MACH*);
static void sfn_time(AUTH_MACH*);
static void sfn_ipaddr(AUTH_MACH*);
static void sfn_exec_wait(AUTH_MACH*);
static void sfn_cleanup_cbkid(AUTH_MACH*);
static void sfn_menu(AUTH_MACH*);
static void sfn_ack(AUTH_MACH*);
static void sfn_exec_nowait(AUTH_MACH*);
static void sfn_reject(AUTH_MACH*);
static VALUE_PAIR *timeout_pair(AUTH_MACH *m);
static int check_expiration(AUTH_MACH *m);


struct auth_state_s {
        enum auth_state this;
        enum auth_state next;
        int             attr;
        enum list_id    list;
        void            (*sfn)(AUTH_MACH*);
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
        
        as_time,         as_eval,
                         DA_LOGIN_TIME,   L_check, sfn_time,
        
        as_eval,         as_scheme,
                         0,               L_null,  sfn_eval_reply,

        as_scheme,       as_ipaddr,
                         DA_SCHEME_PROCEDURE, L_reply, sfn_scheme,
        
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

static void auth_log(AUTH_MACH *m, char *diag, char *pass, char *reason,
                     char *addstr);
static int is_log_mode(AUTH_MACH *m, int mask);
static void auth_format_msg(AUTH_MACH *m, int msg_id);
static char *auth_finish_msg(AUTH_MACH *m);

void
auth_log(m, diag, pass, reason, addstr)
        AUTH_MACH *m;
        char *diag;
        char *pass;
        char *reason;
        char *addstr;
{
        if (reason)
                radlog_req(L_NOTICE, m->req,
			   "%s [%s%s%s]: %s%s, CLID %s",
			   diag,
			   m->namepair->strvalue,
			   pass ? "/" : "",
			   pass ? pass : "",
			   reason,
			   addstr ? addstr : "",
			   m->clid);
        else
                radlog_req(L_NOTICE, m->req,
			   "%s [%s%s%s], CLID %s",
			   diag,
			   m->namepair->strvalue,
			   pass ? "/" : "",
			   pass ? pass : "",
			   m->clid);
}

int
is_log_mode(m, mask)
        AUTH_MACH *m;
        int mask;
{
        int mode = log_mode;
        int xmask = 0;
#ifdef DA_LOG_MODE_MASK
        VALUE_PAIR *p;

        for (p = avl_find(m->user_check, DA_LOG_MODE_MASK);
             p;
             p = p->next ? avl_find(p->next, DA_LOG_MODE_MASK) : NULL)
                xmask |= p->lvalue;
        for (p = avl_find(m->req->request, DA_LOG_MODE_MASK);
             p;
             p = p->next ? avl_find(p->next, DA_LOG_MODE_MASK) : NULL)
                xmask |= p->lvalue;
#endif
        return (mode & ~xmask) & mask;
}

void
auth_format_msg(m, msg_id)
        AUTH_MACH *m;
        int msg_id;
{
        int len = strlen(message_text[msg_id]);
        obstack_grow(&m->msg_stack, message_text[msg_id], len);
}

char *
auth_finish_msg(m)
        AUTH_MACH *m;
{
        if (m->user_msg)
                obstack_grow(&m->msg_stack, m->user_msg, strlen(m->user_msg));
        obstack_1grow(&m->msg_stack, 0);
        return radius_xlate(&m->msg_stack, obstack_finish(&m->msg_stack),
                            m->req, m->user_reply);
}


/*
 * Check if account has expired, and if user may login now.
 */
int
check_expiration(m)
        AUTH_MACH *m;
{
        int result, rc;
        VALUE_PAIR *pair;
        
        result = AUTH_OK;
        if (pair = avl_find(m->user_check, DA_EXPIRATION)) {
                rc = pw_expired(pair->lvalue);
                if (rc < 0) {
                        result = AUTH_FAIL;
                        auth_format_msg(m, MSG_PASSWORD_EXPIRED);
                } else if (rc > 0) {
                        VALUE_PAIR *pair;
                        pair = avp_create(DA_PASSWORD_EXPIRE_DAYS, 0, NULL,
                                          rc/86400);
                        avl_add_pair(&m->user_reply, pair);
                        auth_format_msg(m, MSG_PASSWORD_EXPIRE_WARNING);
                }
        }

        return result;
}


int
rad_authenticate(radreq, activefd)
        RADIUS_REQ  *radreq;
        int        activefd;
{
        enum auth_state oldstate;
        struct auth_state_s *sp;
        struct auth_mach m;
#ifdef USE_LIVINGSTON_MENUS
        VALUE_PAIR *pair_ptr;
#endif

        log_open(L_AUTH);
        
#ifdef USE_LIVINGSTON_MENUS
        /*
         * If the request is processing a menu, service it here.
         */
        if ((pair_ptr = avl_find(radreq->request, DA_STATE)) != NULL &&
            strncmp(pair_ptr->strvalue, "MENU=", 5) == 0) {
            process_menu(radreq, activefd);
            return 0;
        }
#endif

        m.req = radreq;
        m.activefd = activefd;
        m.user_check = NULL;
        m.user_reply = NULL;
        m.check_pair = NULL;
        m.timeout_pair = NULL;
        m.user_msg   = NULL;
        obstack_init(&m.msg_stack);
        /*FIXME: this should have been cached by rad_auth_init */
        m.namepair = avl_find(m.req->request, DA_USER_NAME);

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
                        if (p = avl_find(p, sp->attr))
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
        avl_free(m.user_check);
        avl_free(m.user_reply);
        if (m.user_msg)
                free(m.user_msg);
        obstack_free(&m.msg_stack, NULL);
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
        AUTH_MACH *m;
{
        int proxied = 0;
        RADIUS_REQ *radreq = m->req;
        VALUE_PAIR *pair_ptr;
        
        /* If this request got proxied to another server, we need
           to add an initial Auth-Type: Auth-Accept for success,
           Auth-Reject for fail. We also need to add the reply
           pairs from the server to the initial reply. */
        if (radreq->server_code == RT_AUTHENTICATION_REJECT ||
            radreq->server_code == RT_AUTHENTICATION_ACK) {
                m->user_check = avp_create(DA_AUTH_TYPE, 0, NULL, 0);
                proxied = 1;
        }
        if (radreq->server_code == RT_AUTHENTICATION_REJECT)
                m->user_check->lvalue = DV_AUTH_TYPE_REJECT;
        if (radreq->server_code == RT_AUTHENTICATION_ACK)
                m->user_check->lvalue = DV_AUTH_TYPE_ACCEPT;

        if (radreq->server_reply) {
                m->user_reply = radreq->server_reply;
                radreq->server_reply = NULL;
        }

        if (pair_ptr = avl_find(radreq->request, DA_CALLING_STATION_ID)) 
                m->clid = pair_ptr->strvalue;
        else
                m->clid = _("unknown");

        /*
         * Get the user from the database
         */
        if (user_find(m->namepair->strvalue, radreq,
                      &m->user_check, &m->user_reply) != 0
            && !proxied) {

                if (is_log_mode(m, RLOG_AUTH)) 
                        auth_log(m, _("Invalid user"), NULL, NULL, NULL);

                /* Send reject packet with proxy-pairs as a reply */
                newstate(as_reject);
                avl_free(m->user_reply);
                m->user_reply = NULL;
        }
}

void
sfn_eval_reply(m)
        AUTH_MACH *m;
{
        VALUE_PAIR *p;
        int errcnt = 0;
        
        for (p = m->user_reply; p; p = p->next) {
                if (p->eval) {
                        Datatype type;
                        Datum datum;
 
                        if (interpret(p->strvalue, m->req, &type, &datum)) {
                                errcnt++;
                                continue;
                        }
                        free_string(p->strvalue);
                        switch (type) {
                        case Integer:
                                p->lvalue = datum.ival;
                                break;
                        case String:
                                p->strvalue = datum.sval;
                                p->strlength = strlen(p->strvalue);
                                break;
                        default:
                                abort();
                        }
                        p->eval = 0;
                }
        }
        if (errcnt)
                newstate(as_reject);
}               

void
sfn_scheme(m)
        AUTH_MACH *m;
{
#ifdef USE_SERVER_GUILE
        VALUE_PAIR *p;
        VALUE_PAIR *reply;
        
        if (!use_guile) {
                radlog_req(L_ERR, m->req,
                       _("Guile authentication disabled in config"));
                newstate(as_reject);
                return;
        }

        reply = avl_dup(m->user_reply);
        for (p = avl_find(reply, DA_SCHEME_PROCEDURE);
             p;
             p = avl_find(p->next, DA_SCHEME_PROCEDURE)) {
                if (scheme_auth(p->strvalue,
                                m->req, m->user_check, &m->user_reply)) {
                        newstate(as_reject);
                        break;
                }
        }
        avl_delete(&m->user_reply, DA_SCHEME_PROCEDURE);
        avl_free(reply);
#else
        radlog_req(L_ERR, m->req,
               _("Guile authentication not available"));
        newstate(as_reject);
        return;
#endif
}

void
sfn_validate(m)
        AUTH_MACH *m;
{
        RADIUS_REQ *radreq = m->req;
        int rc;
        char *reason = NULL;
	
	rc = rad_check_password(radreq,
				m->user_check, m->namepair,
				&m->user_msg,
				m->userpass);


	if (rc != AUTH_OK) { 
		stat_inc(auth, radreq->ipaddr, num_rejects);

		if (is_log_mode(m, RLOG_AUTH)) {
			switch (rc) {
			case AUTH_REJECT:
				auth_log(m, _("Rejected"),
					 NULL, NULL, NULL);  
				break;

			case AUTH_IGNORE:
				auth_log(m, _("Ignored"),
					 NULL, NULL, NULL);
				newstate(as_stop);
				return; /*NOTE: do not break!*/
                                
			case AUTH_NOUSER:
				auth_log(m, _("Invalid user"),
					 NULL, NULL, NULL);
				break;
                                
			case AUTH_FAIL:
				auth_log(m,
					 _("Login incorrect"),
					 is_log_mode(m, RLOG_FAILED_PASS) ?
					 m->userpass : NULL,
					 NULL, NULL);
				break;

			default:
				insist_fail("sfn_validate");
			}
		}
		newstate(as_reject);
		auth_format_msg(m, MSG_ACCESS_DENIED);
	}

	rc = check_expiration(m);

	if (rc != AUTH_OK) {
                newstate(as_reject);
                if (is_log_mode(m, RLOG_AUTH)) {
                        auth_log(m,
                                 _("Login incorrect"),
                                 is_log_mode(m, RLOG_FAILED_PASS) ?
				 m->userpass : NULL,
                                 _("Password expired"), NULL);
                }
        }
}

void
sfn_service(m)
        AUTH_MACH *m;
{
        /* FIXME: Other service types should also be handled,
         *        I suppose     
         */
        if (m->check_pair->lvalue != DV_SERVICE_TYPE_AUTHENTICATE_ONLY)
                return;
        newstate(as_ack);
}

void
sfn_disable(m)
        AUTH_MACH *m;
{
        if (get_deny(m->namepair->strvalue)) {
                auth_format_msg(m, MSG_ACCOUNT_CLOSED);
                auth_log(m, _("Account disabled"), NULL, NULL, NULL);
                newstate(as_reject);
        }
}

void
sfn_service_type(m)
        AUTH_MACH *m;
{
        if (m->check_pair->lvalue == DV_SERVICE_TYPE_AUTHENTICATE_ONLY) {
                auth_log(m, _("Login rejected"), NULL,
                         _("Authenticate only user"), NULL);
                auth_format_msg(m, MSG_ACCESS_DENIED);
                newstate(as_reject);
        }
}

void
sfn_realmuse(m)
        AUTH_MACH *m;
{
        if (!m->req->realm)
                return;
        
        if (rad_check_realm(m->req->realm) == 0)
                return;
        auth_format_msg(m, MSG_REALM_QUOTA);
        auth_log(m, _("Login failed"), NULL,
                 _("realm quota exceeded for "), m->req->realm->realm);
        newstate(as_reject);
}

void
sfn_simuse(m)
        AUTH_MACH *m;
{
        char  name[AUTH_STRING_LEN];
        int rc;
        int count;
        
        strip_username(strip_names,
                       m->namepair->strvalue, m->user_check, name);
        rc = rad_check_multi(name, m->req->request,
                             m->check_pair->lvalue, &count);
        avl_add_pair(&m->user_reply,
                     avp_create(DA_SIMULTANEOUS_USE, 0, NULL, count));
        if (!rc)
                return;

        auth_format_msg(m,
                        (m->check_pair->lvalue > 1) ?
                        MSG_MULTIPLE_LOGIN : MSG_SECOND_LOGIN);

        radlog_req(L_WARN, m->req,
		   _("Multiple logins: [%s] max. %ld%s, CLID %s"),
               m->namepair->strvalue,
               m->check_pair->lvalue,
		   rc == 2 ? _(" [MPP attempt]") : "",
		   m->clid);
        newstate(as_reject);
}

VALUE_PAIR *
timeout_pair(m)
        AUTH_MACH *m;
{
        if (!m->timeout_pair &&
            !(m->timeout_pair = avl_find(m->user_reply, DA_SESSION_TIMEOUT))) {
                m->timeout_pair = avp_create(DA_SESSION_TIMEOUT,
                                              0, NULL, 0);
                avl_add_pair(&m->user_reply, m->timeout_pair);
        }
        return m->timeout_pair;
}

void
sfn_time(m)
        AUTH_MACH *m;
{
        int rc;
        time_t t;
        unsigned rest;
        
        time(&t);
        rc = ts_check(m->check_pair->strvalue, &t, &rest, NULL);
        if (rc == 1) {
                /*
                 * User called outside allowed time interval.
                 */
                auth_format_msg(m, MSG_TIMESPAN_VIOLATION);
                radlog_req(L_ERR,
			   m->req,
       _("Outside allowed timespan, time allowed: %s"),
			   m->check_pair->strvalue);
                newstate(as_reject);
        } else if (rc == 0) {
                /*
                 * User is allowed, but set Session-Timeout.
                 */
                timeout_pair(m)->lvalue = rest;
                debug(2, ("user %s, span %s, timeout %d",
                          m->namepair->strvalue,
                          m->check_pair->strvalue,
                          rest));
        }
}

void
sfn_ipaddr(m)
        AUTH_MACH *m;
{
        VALUE_PAIR *p, *tmp, *pp;
        
        /* Assign an IP if necessary */
        if (!avl_find(m->user_reply, DA_FRAMED_IP_ADDRESS)) {
#if 0
                /* **************************************************
                 * Keep it here until IP allocation is ready
                 */
                if (p = alloc_ip_pair(m->namepair->strvalue, m->req))
                        avl_add_pair(&m->user_reply, p);
                else
#endif  
                if (p = avl_find(m->req->request, DA_FRAMED_IP_ADDRESS)) {
                        /* termserver hint */
                        avl_add_pair(&m->user_reply, avp_dup(p));
                        if (p = avl_find(m->req->request,
                                         DA_ADD_PORT_TO_IP_ADDRESS))
                                avl_add_pair(&m->user_reply, avp_dup(p));
                }
        }
        
        if ((p = avl_find(m->user_reply, DA_FRAMED_IP_ADDRESS)) &&
            (tmp = avl_find(m->user_reply, DA_ADD_PORT_TO_IP_ADDRESS)) &&
            tmp->lvalue &&
            (pp = avl_find(m->req->request, DA_NAS_PORT_ID)))
                /* NOTE: This only works because IP numbers are stored in
                 * host order throughout the program.
                 */
                p->lvalue += pp->lvalue;
                
        avl_delete(&m->user_reply, DA_ADD_PORT_TO_IP_ADDRESS);
}

void
sfn_exec_wait(m)
        AUTH_MACH *m;
{
	int rc;
	
	switch (m->check_pair->strvalue[0]) {
	case '/':
		/* radius_exec_program() returns -1 on
		   fork/exec errors, or >0 if the exec'ed program
		   had a non-zero exit status.
		*/
		rc = radius_exec_program(m->check_pair->strvalue,
					 m->req,
					 &m->user_reply,
					 1,
					 &m->user_msg);
		break;

	case '|':
		rc = filter_auth(m->check_pair->strvalue+1,
				 m->req,
				 &m->user_reply);
		break;

	default:
		rc = 1;
	}

	if (rc != 0) {
		newstate(as_reject);

		auth_format_msg(m, MSG_ACCESS_DENIED);
		
		if (is_log_mode(m, RLOG_AUTH)) {
			auth_log(m, _("Login incorrect"),
				 NULL,
				 _("external check failed"), NULL);
		}
	}
}

void
sfn_exec_nowait(m)
        AUTH_MACH *m;
{
        /*FIXME: do we need to pass user_reply here? */
        radius_exec_program(m->check_pair->strvalue,
                            m->req, &m->user_reply,
                            0, NULL);
}

void
sfn_cleanup_cbkid(m)
        AUTH_MACH *m;
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
                avl_delete(&m->user_reply, *ip);
}

void
sfn_menu(m)
        AUTH_MACH *m;
{
#ifdef USE_LIVINGSTON_MENUS
        char *msg;
        char state_value[MAX_STATE_VALUE];
                
        msg = get_menu(m->check_pair->strvalue);
        snprintf(state_value, sizeof(state_value),
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
        AUTH_MACH *m;
{
        debug(1, ("ACK: %s", m->namepair->strvalue));
        
        stat_inc(auth, m->req->ipaddr, num_accepts);

        rad_send_reply(RT_AUTHENTICATION_ACK,
                       m->req,
                       m->user_reply,
                       auth_finish_msg(m),
                       m->activefd);
        
        if (is_log_mode(m, RLOG_AUTH)) {
                auth_log(m, _("Login OK"),
                         is_log_mode(m, RLOG_AUTH_PASS) ? m->userpass : NULL,
                         NULL, NULL);
        }

        if (timeout_pair(m)) {
                debug(5,
                        ("timeout for [%s] is set to %ld sec",
                         m->namepair->strvalue, timeout_pair(m)->lvalue));
        }
}

void
sfn_reject(m)
        AUTH_MACH *m;
{
        debug(1, ("REJECT: %s", m->namepair->strvalue));
        rad_send_reply(RT_AUTHENTICATION_REJECT,
                       m->req,
                       m->user_reply,
                       auth_finish_msg(m),
                       m->activefd);
        stat_inc(auth, m->req->ipaddr, num_rejects);
}

void
req_decrypt_password(password, req, pair)
        char *password;
        RADIUS_REQ *req;
        VALUE_PAIR *pair; /* Password pair */
{
        NAS *nas;
        char *s;
        
        if (!pair) {
                pair = avl_find(req->request, DA_USER_PASSWORD);
                if (!pair)
                        return;
        }
        /* Determine whether we need to use broken decoding */
        nas = nas_request_to_nas(req);
        if (nas
            && (s = envar_lookup(nas->args, "broken_pass")) != NULL
            && s[0] == '1')
                decrypt_password_broken(password, pair,
                                        req->vector, req->secret);
        else
                decrypt_password(password, pair,
                                 req->vector, req->secret);
}
