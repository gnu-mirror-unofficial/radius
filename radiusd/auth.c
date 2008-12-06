/* This file is part of GNU Radius
   Copyright (C) 2000,2001,2002,2003,2004,
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

#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#endif

#if defined(PWD_SHADOW)
# if PWD_SHADOW == SHADOW
#  include <shadow.h>
#  define STRUCT_SHADOW_PASSWD struct spwd
#  define SHADOW_PASSWD_ENCRYPTED(s) ((s)->sp_pwdp)
#  define GETSPNAM getspnam
#  if defined(HAVE_STRUCT_SPWD_SP_EXPIRE)
#   define SHADOW_PASSWD_EXPIRE(s) ((s)->sp_expire)
#  endif
# else /*OSFC2*/
#  include <sys/security.h>
#  include <prot.h>
#  define STRUCT_SHADOW_PASSWD struct pr_passwd
#  define SHADOW_PASSWD_ENCRYPTED(s) ((s)->ufld.fd_encrypt)
#  define GETSPNAM getprpwnam
#  ifdef HAVE_STRUCT_PR_PASSWD_UFLG_FG_LOCK
#   define SHADOW_PASSWD_LOCK(s) ((s)->->uflg.fg_lock)
#  endif
# endif				    
#else
# define STRUCT_SHADOW_PASSWD struct passwd
# define GETSPNAM(n) NULL
# define SHADOW_PASSWD_ENCRYPTED(s) NULL
#endif

#include <radiusd.h>
#include <timestr.h>
#include <rewrite.h>

char *username_valid_chars;

/* Check if the username is valid. Valid usernames consist of 
   alphanumeric characters and symbols from username_valid_chars[]
   array */
int
check_user_name(char *p)
{
        for (; *p && (isalnum(*p) || strchr(username_valid_chars, *p)); p++)
                ;
        return *p;
}

LOCK_DECLARE(lock)

#ifdef EMBEDDED_EXPIRATION_INFO	
static char base64[] =         /* 0 ... 63 => ascii - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static int
from_base64(u_char *data, int len, unsigned int *value)
{
	int i;

	*value = 0;
	for (i = len-1; i >= 0; i--) {
		char *p = strchr(base64, data[i]);
		if (!p)
			return 1;
		*value <<= 6;
		*value += p - base64;
	}
	return 0;
}
	
static int
decode_aging_info(char *p, u_int *maxweeks, u_int *minweeks, u_int *lastchange)
{
	if (from_base64(p, 1, maxweeks))
		return 1;
	p++;
	if (from_base64(p, 1, minweeks))
		return 1;
	p++;
	if (from_base64(p, 2, lastchange))
		return 1;
	if (p[2])
		return 1;
	return 0;
}
#endif	
	
static enum auth_status
unix_expiration(char *name, time_t *exp)
{
	enum auth_status status = auth_ok;
#ifdef SHADOW_PASSWD_EXPIRE
	STRUCT_SHADOW_PASSWD *spwd = GETSPNAM(name);

	if (spwd && SHADOW_PASSWD_EXPIRE(spwd) > 0) {
		time_t t = time(NULL);
		if (t > SHADOW_PASSWD_EXPIRE(spwd) * SECONDS_PER_DAY)
			status = auth_account_expired;
		else {
			*exp = SHADOW_PASSWD_EXPIRE(spwd) * SECONDS_PER_DAY - t;
			status = auth_valid;
		}
	}
#elif defined(HAVE_STRUCT_PASSWD_PW_EXPIRE)
	struct passwd *pwd;
	struct timeval tv;
	time_t t = 0;
	
	if (pwd = getpwnam(name)) {
		gettimeofday(&tv, NULL);
		if (pwd->pw_expire) {
			if (tv.tv_sec >= pwd->pw_expire)
				status = auth_account_expired;
			else {
				t = pwd->pw_change - tv.tv_sec;
				status = auth_valid;
			}
		}
# if defined(HAVE_STRUCT_PASSWD_PW_CHANGE)
		if (pwd->pw_change) {
			if (tv.tv_sec >= pwd->pw_change)
				status = auth_password_expired;
			else if (status == auth_ok
				 || pwd->pw_change - tv.tv_sec < t) {
				t = pwd->pw_change - tv.tv_sec;
				status = auth_valid;
			}
		}
		*exp = t;
# endif
	}
#endif
#ifdef EMBEDDED_EXPIRATION_INFO
	if (status == auth_ok) {
		struct passwd *pwd;
		char *p;
#define SECS_IN_WEEK 604800
	
		if (pwd = getpwnam(name)) {
			p = strchr(pwd->pw_passwd, ',');
			if (p) {
				u_int maxweeks, minweeks, lastchange;
			
				if (decode_aging_info(p+1,
						      &maxweeks,
						      &minweeks,
						      &lastchange) == 0) {
					time_t now = time(NULL);
					time_t nweeks = now / SECS_IN_WEEK
						        - lastchange;
					
					if (maxweeks == minweeks)
						return auth_password_expired;
				
					if (nweeks >= minweeks
					    && nweeks >= maxweeks)
						return auth_password_expired;

					*exp = (maxweeks - nweeks)
						* SECS_IN_WEEK
						+ now % SECS_IN_WEEK;
					status = auth_valid;
				} else { /* Invalid password data? */
					grad_log(GRAD_LOG_NOTICE,
						 _("Invalid password aging information for user '%s'"), name);
					status = auth_fail;
				}
			}
		}
	}
#endif
	return status;
}
	
static int
unix_pass(char *name, char *passwd)
{
        int rc;
        char *encpw;
        int pwlen;
        char *encrypted_pass = NULL;
	STRUCT_SHADOW_PASSWD *spwd;

	LOCK_SET(lock);
	if (spwd = GETSPNAM(name))
                encrypted_pass = SHADOW_PASSWD_ENCRYPTED(spwd);
	else { /* Try to get encrypted password from password file */
		struct passwd *pwd;

		if (pwd = getpwnam(name)) 
			encrypted_pass = pwd->pw_passwd;
	}

#ifdef SHADOW_PASSWD_LOCK
	if (encrypted_pass) {
		/* Check if the account is locked. */
		if (SHADOW_PASSWD_LOCK(spwd) != 1) {
			grad_log(GRAD_LOG_NOTICE,
			         "unix_pass: [%s]: %s",
			         name, _("account locked"));
			encrypted_pass = NULL;
		}
	}
#endif 

	if (encrypted_pass) {
		if (encrypted_pass[0] == 0)
			encrypted_pass = NULL;
		else
			encrypted_pass = grad_estrdup(encrypted_pass);
	}
	
	LOCK_RELEASE(lock);

        if (!encrypted_pass)
                return -1;

        /*
         * Check encrypted password.
         */
        pwlen = strlen(encrypted_pass);
        encpw = grad_emalloc(pwlen+1);
#ifdef EMBEDDED_EXPIRATION_INFO
 {
	/* Some systems append expiration data to the encrypted password */
	char *p = strchr(encrypted_pass, ',');
	if (p) 
		pwlen = p - encrypted_pass;
 }
#endif
        rc = grad_md5crypt(passwd, encrypted_pass, encpw, pwlen+1) == NULL
                || strlen (encpw) != pwlen
		|| memcmp(encpw, encrypted_pass, pwlen);
        grad_free(encpw);
	grad_free(encrypted_pass);
        if (rc)
                return -1;

        return 0;
}

int
rad_auth_check_username(radiusd_request_t *radreq, int activefd)
{
        grad_avp_t *namepair = grad_avl_find(radreq->request->avlist,
					     DA_USER_NAME);

	log_open(GRAD_LOG_AUTH);

        if (grad_avp_null_string_p(namepair)) 
                grad_log_req(GRAD_LOG_ERR, radreq->request, _("No username"));
	else if (check_user_name(namepair->avp_strvalue)) 
                grad_log_req(GRAD_LOG_ERR, radreq->request, _("Malformed username"));
	else
		return 0;

	/* Process a malformed request */
	if (auth_reject_malformed_names) 
		radius_send_reply(RT_ACCESS_REJECT, radreq,
				  NULL,
				  message_text[MSG_ACCESS_DENIED],
				  activefd);
	else
		stat_inc(auth, radreq->request->ipaddr, num_bad_req);
	return -1;
}

/* Initial step of authentication. */
int
rad_auth_init(radiusd_request_t *radreq, int activefd)
{
	grad_locus_t loc;
	
	log_open(GRAD_LOG_AUTH);
                
        if (auth_detail)
                write_detail(radreq, REQ_AUTH_ZERO, R_AUTH);

        /*
         * See if the user has access to this huntgroup.
         */
        if (!huntgroup_access(radreq, &loc)) {
                grad_log_req(GRAD_LOG_NOTICE, radreq->request,
			     _("Access denied by huntgroup %s:%d"),
			     loc.file, loc.line);
                radius_send_reply(RT_ACCESS_REJECT, radreq,
                                  radreq->request->avlist, NULL, activefd);
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
        as_disable, 
        as_realmuse,
        as_simuse, 
        as_time, 
        as_scheme,
        as_ipaddr, 
        as_exec_wait, 
        as_cleanup_cbkid, 
        as_menu_challenge,
        as_ack, 
        as_exec_nowait, 
        as_stop, 
        as_reject,
	as_reject_cleanup,
        AS_COUNT
};

enum list_id {
        L_null,
        L_req,
        L_reply,
        L_check
};

typedef struct auth_mach {
        radiusd_request_t *req;
        grad_avp_t *user_check;
        grad_avp_t *user_reply;
        int        activefd;
        
        grad_avp_t *namepair;
        grad_avp_t *check_pair;
        char       userpass[GRAD_STRING_LENGTH+1];

        char       *user_msg;
        struct obstack msg_stack;
        
        enum auth_state state;
} AUTH_MACH;

static void sfn_init(AUTH_MACH*);
static void sfn_validate(AUTH_MACH*);
static void sfn_scheme(AUTH_MACH*);
static void sfn_disable(AUTH_MACH*);
static void sfn_realmuse(AUTH_MACH*);
static void sfn_simuse(AUTH_MACH*);
static void sfn_time(AUTH_MACH*);
static void sfn_ipaddr(AUTH_MACH*);
static void sfn_exec_wait(AUTH_MACH*);
static void sfn_cleanup_cbkid(AUTH_MACH*);
static void sfn_menu_challenge(AUTH_MACH*);
static void sfn_ack(AUTH_MACH*);
static void sfn_exec_nowait(AUTH_MACH*);
static void sfn_reject(AUTH_MACH*);
static void sfn_reject_cleanup(AUTH_MACH *m);
static int check_expiration(AUTH_MACH *m);


struct auth_state_s {
        enum auth_state this;
        enum auth_state next;
        int             attr;
        enum list_id    list;
        void            (*sfn)(AUTH_MACH*);
};

struct auth_state_s states[] = {
        { as_init,         as_validate,
                         0,               L_null,     sfn_init },

	{ as_validate,     as_disable,
                         0,               L_null,     sfn_validate },
        
        { as_disable,      as_realmuse,
                         0,               L_null,     sfn_disable },
        
        { as_realmuse,     as_simuse,
                         0,               L_null,     sfn_realmuse }, 
        
        { as_simuse,       as_time,
                         DA_SIMULTANEOUS_USE, L_check, sfn_simuse },
        
        { as_time,         as_scheme,
                         DA_LOGIN_TIME,   L_check, sfn_time },
        
        { as_scheme,       as_ipaddr,
                         DA_SCHEME_PROCEDURE, L_reply, sfn_scheme },
        
        { as_ipaddr,       as_exec_wait,
                         0,               L_null, sfn_ipaddr },
        
        { as_exec_wait,    as_cleanup_cbkid,
                         DA_EXEC_PROGRAM_WAIT, L_reply, sfn_exec_wait },
        
        { as_cleanup_cbkid,as_menu_challenge,
                         DA_CALLBACK_ID,  L_reply, sfn_cleanup_cbkid },
        
        { as_menu_challenge,         as_ack,
                         DA_MENU,         L_reply, sfn_menu_challenge },
        
        { as_ack,          as_exec_nowait,
                         0,               L_null, sfn_ack },
        
        { as_exec_nowait,  as_stop,
                         DA_EXEC_PROGRAM, L_reply, sfn_exec_nowait },
        
        { as_stop,         as_stop,
                         0,               L_null, NULL },
        
        { as_reject,       as_stop,
                         0,               L_null, sfn_reject },
	
        { as_reject_cleanup, as_reject,
                         0,               L_null, sfn_reject_cleanup },
};

static int is_log_mode(AUTH_MACH *m, int mask);
static void auth_format_msg(AUTH_MACH *m, int msg_id);
static char *auth_finish_msg(AUTH_MACH *m);

static void
auth_log(AUTH_MACH *m, const char *diag, const char *pass,
	 const char *reason, const char *addstr)
{
        if (reason)
                grad_log_req(GRAD_LOG_NOTICE, m->req->request,
			     "%s [%s%s%s]: %s%s",
			     diag,
			     m->namepair->avp_strvalue,
			     pass ? "/" : "",
			     pass ? pass : "",
			     reason,
			     addstr ? addstr : "");
        else
                grad_log_req(GRAD_LOG_NOTICE, m->req->request,
			     "%s [%s%s%s]",
			     diag,
			     m->namepair->avp_strvalue,
			     pass ? "/" : "",
			     pass ? pass : "");
}

int
is_log_mode(AUTH_MACH *m, int mask)
{
        int mode = log_mode;
        int xmask = 0;
#ifdef DA_LOG_MODE_MASK
        grad_avp_t *p;

        for (p = grad_avl_find(m->user_check, DA_LOG_MODE_MASK);
             p;
             p = p->next ? grad_avl_find(p->next, DA_LOG_MODE_MASK) : NULL)
                xmask |= p->avp_lvalue;
        for (p = grad_avl_find(m->req->request->avlist, DA_LOG_MODE_MASK);
             p;
             p = p->next ? grad_avl_find(p->next, DA_LOG_MODE_MASK) : NULL)
                xmask |= p->avp_lvalue;
#endif
        return (mode & ~xmask) & mask;
}

void
auth_format_msg(AUTH_MACH *m, int msg_id)
{
        int len = strlen(message_text[msg_id]);
        obstack_grow(&m->msg_stack, message_text[msg_id], len);
}

char *
auth_finish_msg(AUTH_MACH *m)
{
        if (m->user_msg)
                obstack_grow(&m->msg_stack, m->user_msg, strlen(m->user_msg));
        obstack_1grow(&m->msg_stack, 0);
        return radius_xlate(&m->msg_stack, obstack_finish(&m->msg_stack),
                            m->req->request, m->user_reply);
}

/* Check password. */
static enum auth_status 
rad_check_password(radiusd_request_t *radreq, AUTH_MACH *m, time_t *exp)
{
        char *ptr;
        char *real_password = NULL;
        char name[GRAD_STRING_LENGTH];
        grad_avp_t *auth_item;
        grad_avp_t *tmp;
        int auth_type = -1;
        int length;
        enum auth_status result = auth_ok;
        char *authdata = NULL;
        char pw_digest[GRAD_AUTHENTICATOR_LENGTH];
        int pwlen;
        char *pwbuf;
        char *challenge;
	int challenge_len;
	
        m->userpass[0] = 0;

        /* Process immediate authentication types */
        if ((tmp = grad_avl_find(m->user_check, DA_AUTH_TYPE)) != NULL)
                auth_type = tmp->avp_lvalue;

	switch (auth_type) {
	case DV_AUTH_TYPE_ACCEPT:
                return auth_ok;

	case DV_AUTH_TYPE_REJECT:
                return auth_reject;

	case DV_AUTH_TYPE_IGNORE:
		return auth_ignore;
	}

        /* Find the password sent by the user. If it's not present,
           authentication fails. */
        
        if (auth_item = grad_avl_find(radreq->request->avlist, DA_CHAP_PASSWORD))
                auth_type = DV_AUTH_TYPE_LOCAL;
        else
                auth_item = grad_avl_find(radreq->request->avlist, DA_USER_PASSWORD);
        
        /* Decrypt the password. */
        if (auth_item) {
                if (auth_item->avp_strlength == 0)
                        m->userpass[0] = 0;
                else
                        req_decrypt_password(m->userpass, radreq->request,
                                             auth_item);
        } else /* if (auth_item == NULL) */
                return auth_fail;
        
        /* Set up authentication data */
        if ((tmp = grad_avl_find(m->user_check, DA_AUTH_DATA)) != NULL) 
                authdata = tmp->avp_strvalue;

        /* Find the 'real' password */
        tmp = grad_avl_find(m->user_check, DA_USER_PASSWORD);
        if (tmp)
                real_password = grad_estrdup(tmp->avp_strvalue);
        else if (tmp = grad_avl_find(m->user_check, DA_PASSWORD_LOCATION)) {
                switch (tmp->avp_lvalue) {
                case DV_PASSWORD_LOCATION_SQL:
#ifdef USE_SQL
                        real_password = radiusd_sql_pass(radreq, authdata);
                        if (!real_password)
                                return auth_nouser;
			grad_avl_add_pair(&m->user_check,
					  grad_avp_create_string(DA_USER_PASSWORD, real_password));
                        break;
#endif
                /* NOTE: add any new location types here */
                default:
                        grad_log(GRAD_LOG_ERR,
                                 _("unknown Password-Location value: %ld"),
                                 tmp->avp_lvalue);
                        return auth_fail;
                }
        }

        /* Process any prefixes/suffixes. */
        strip_username(1, m->namepair->avp_strvalue, m->user_check, name);

        GRAD_DEBUG4(1, "auth_type=%d, userpass=%s, name=%s, password=%s",
	            auth_type, m->userpass, name,
	            real_password ? real_password : "NONE");

        switch (auth_type) {
        case DV_AUTH_TYPE_SYSTEM:
                GRAD_DEBUG(1, "auth: System");
                if (unix_pass(name, m->userpass) != 0)
                        result = auth_fail;
		else
			result = unix_expiration(name, exp);
                break;
		
        case DV_AUTH_TYPE_PAM:
#ifdef USE_PAM
                GRAD_DEBUG(1, "auth: Pam");
                /* Provide defaults for authdata */
                if (authdata == NULL &&
                    (tmp = grad_avl_find(m->user_check, DA_PAM_AUTH)) != NULL) {
                        authdata = tmp->avp_strvalue;
                }
                authdata = authdata ? authdata : PAM_DEFAULT_TYPE;
                if (pam_pass(name, m->userpass, authdata, &m->user_msg) != 0)
                        result = auth_fail;
#else
                grad_log_req(GRAD_LOG_ERR, radreq->request,
                             _("PAM authentication not available"));
                result = auth_nouser;
#endif
                break;

        case DV_AUTH_TYPE_CRYPT_LOCAL:
                GRAD_DEBUG(1, "auth: Crypt");
                if (real_password == NULL) {
                        result = auth_fail;
                        break;
                }
                pwlen = strlen(real_password)+1;
                pwbuf = grad_emalloc(pwlen);
                if (!grad_md5crypt(m->userpass, real_password, pwbuf, pwlen))
                        result = auth_fail;
                else if (strcmp(real_password, pwbuf) != 0)
                        result = auth_fail;
                GRAD_DEBUG1(1, "pwbuf: %s", pwbuf);
                grad_free(pwbuf);
                break;
                
        case DV_AUTH_TYPE_LOCAL:
                GRAD_DEBUG(1, "auth: Local");
                /* Local password is just plain text. */
                if (auth_item->attribute != DA_CHAP_PASSWORD) {
                        if (real_password == NULL ||
                            strcmp(real_password, m->userpass) != 0)
                                result = auth_fail;
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
                strcpy(m->userpass, "{chap-password}");
		
                if (real_password == NULL) {
                        result = auth_fail;
                        break;
                }

		/* Compute the length of the password buffer and
		   allocate it */
                length = strlen(real_password);
		
                if (tmp = grad_avl_find(radreq->request->avlist,
					DA_CHAP_CHALLENGE)) {
                        challenge = tmp->avp_strvalue;
                        challenge_len = tmp->avp_strlength;
                } else {
                        challenge = radreq->request->authenticator;
                        challenge_len = GRAD_AUTHENTICATOR_LENGTH;
                }

                pwlen = 1 + length + challenge_len;
		pwbuf = grad_emalloc(pwlen);
		
                ptr = pwbuf;
                *ptr++ = *auth_item->avp_strvalue;
                memcpy(ptr, real_password, length);
                ptr += length;
                memcpy(ptr, challenge, challenge_len);

		/* Compute the MD5 hash */
                grad_md5_calc(pw_digest, (u_char*) pwbuf, pwlen);
                grad_free(pwbuf);
		
                /* Compare them */
                if (memcmp(pw_digest, auth_item->avp_strvalue + 1,
			   GRAD_CHAP_VALUE_LENGTH) != 0)
                        result = auth_fail;
                else
                        strcpy(m->userpass, real_password);
                break;
		
        default:
		/* Try loadable modules. */
		result = scheme_try_auth(auth_type, radreq,
					 m->user_check,
					 &m->user_reply) ?  auth_fail : auth_ok;
                break;
        }

        if (real_password) {
                /* just in case: */
                memset(real_password, 0, strlen(real_password)); 
                grad_free(real_password);
        }
        return result;
}

/* Check if account has expired, and if user may login now. */
enum auth_status 
radius_check_expiration(AUTH_MACH *m, time_t *exp)
{
        grad_avp_t *pair;
        
        if (pair = grad_avl_find(m->user_check, DA_EXPIRATION)) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		if (tv.tv_sec > pair->avp_lvalue)
			return auth_account_expired;
		*exp = pair->avp_lvalue - tv.tv_sec;
		return auth_valid;
        }
	return auth_ok;
}


int
rad_authenticate(radiusd_request_t *radreq, int activefd)
{
        enum auth_state oldstate;
        struct auth_state_s *sp;
        struct auth_mach m;

	log_open(GRAD_LOG_AUTH);
        m.req = radreq;
        m.activefd = activefd;
        m.user_check = NULL;
        m.user_reply = NULL;
        m.check_pair = NULL;
        m.user_msg   = NULL;
        obstack_init(&m.msg_stack);

        m.namepair = grad_avl_find(m.req->request->avlist, DA_USER_NAME);

        GRAD_DEBUG1(1, "auth: %s", m.namepair->avp_strvalue); 
        m.state = as_init;

        while (m.state != as_stop) {
                sp = &states[m.state];
                oldstate = m.state;
                if (sp->attr) {
                        grad_avp_t *p;
                        
                        switch (sp->list) {
                        case L_req:
                                p = m.req->request->avlist;
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
                        if (p = grad_avl_find(p, sp->attr))
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
        grad_avl_free(m.user_check);
        grad_avl_free(m.user_reply);
        if (m.user_msg)
                free(m.user_msg);
        obstack_free(&m.msg_stack, NULL);
        memset(m.userpass, 0, sizeof(m.userpass));
        return 0;
}

#if RADIUS_DEBUG
# define newstate(s) do {\
             GRAD_DEBUG2(2, "%d -> %d", m->state, s);\
             m->state = s;\
  } while (0)
#else
# define newstate(s) m->state = s
#endif
                                
        
void
sfn_init(AUTH_MACH *m)
{
        radiusd_request_t *radreq = m->req;
        grad_avp_t *pair_ptr;

	switch (radreq->server_code) {
	case RT_ACCESS_REJECT:
		m->user_check = grad_avp_create_integer(DA_AUTH_TYPE, 
							DV_AUTH_TYPE_REJECT);
		break;

	case RT_ACCESS_ACCEPT:
		m->user_check = grad_avp_create_integer(DA_AUTH_TYPE, 
							DV_AUTH_TYPE_ACCEPT);
		break;

	case 0:
		break;

	default:
		radius_send_reply(radreq->server_code,
			          radreq,
			          radreq->server_reply,
			          NULL,
			          m->activefd);
		newstate(as_stop);
		return;
	}
	
#ifdef USE_LIVINGSTON_MENUS
	/*
	 * If the request is processing a menu, service it here.
	 */
	if (radreq->server_code == 0
	    && (pair_ptr = grad_avl_find(m->req->request->avlist, DA_STATE)) != NULL
	    && strncmp(pair_ptr->avp_strvalue, "MENU=", 5) == 0) {
		menu_reply(m->req, m->activefd);
		newstate(as_stop);
		return;
	}
#endif

	/* If this request was proxied to another server, we need
	   to add the reply pairs from the server to the initial reply.
	   We need to scan and decrypt them first. It could have been
	   done in proxy_receive, but this would mean that their plaintext
	   values would hang around in queue, which is not acceptable. */

        if (radreq->server_reply) {
                m->user_reply =
			radius_decrypt_request_pairs(radreq,
						     radreq->server_reply);
                radreq->server_reply = NULL;
        }

        /*
         * Get the user from the database
         */
        if (user_find(m->namepair->avp_strvalue, radreq,
                      &m->user_check, &m->user_reply) != 0
            && !radreq->server_code) {

                if (is_log_mode(m, RLOG_AUTH)) 
                        auth_log(m, _("No such user"), NULL, NULL, NULL);

		auth_format_msg(m, MSG_ACCESS_DENIED);
                /* Send reject packet with proxy-pairs as a reply */
                newstate(as_reject_cleanup);
        }
}

void
sfn_scheme(AUTH_MACH *m)
{
	grad_avp_t *p;
        grad_avp_t *tmp = NULL;

	grad_avl_move_attr(&tmp, &m->user_reply, DA_SCHEME_PROCEDURE);
	if (scheme_eval_avl (m->req, m->user_check, tmp, &m->user_reply, &p)) {
		if (p) {
			auth_log(m,
				 _("Login rejected"),
				 NULL,
				 _("denied by Scheme procedure "),
				 p->avp_strvalue);
                        newstate(as_reject);
		} else { /* Empty P means that Guile auth is not available */
			newstate(as_reject_cleanup);
		}
	}
	grad_avl_free(tmp);
}

/* Execute an Authentication Failure Trigger, if the one is specified */
static void
auth_failure(AUTH_MACH *m)
{
	grad_avp_t *pair;
	char *cmd;
	
	pair = grad_avl_find(m->user_reply, DA_AUTH_FAILURE_TRIGGER);
	if (!pair) 
		return;

	cmd = util_xlate(&m->msg_stack, pair->avp_strvalue, m->req->request);
	switch (cmd[0]) {
	case '(':
		scheme_eval_unspecified_expr(cmd);
		break;

	case '/':
		radius_exec_command(cmd);
		break;

	default:
		grad_log_req(GRAD_LOG_ERR,
			     m->req->request,
			     _("Invalid Auth-Failure-Trigger value: %s"),
			     cmd);
		grad_log(GRAD_LOG_INFO,
			 _("The value of Auth-Failure-Trigger attribute must begin with '/' or '('."));
	}
}

void
sfn_validate(AUTH_MACH *m)
{
        radiusd_request_t *radreq = m->req;
	enum auth_status rc;
	time_t exp;
	grad_avp_t *pair;
	
	rc = rad_check_password(radreq, m, &exp);

	if (rc == auth_ok) {
		radiusd_sql_auth_result_query(m->req, 0);
		rc = radius_check_expiration(m, &exp);
	} else if (rc == auth_fail) {
		radiusd_sql_auth_result_query(m->req, 1);
		auth_failure(m);
	}
	
	switch (rc) {
	case auth_ok:
		break;

	case auth_valid:
		exp /= SECONDS_PER_DAY;
		if (warning_seconds != 0 && exp < warning_seconds) {
			pair = grad_avp_create_integer(DA_PASSWORD_EXPIRE_DAYS,
						       exp);
			grad_avl_add_pair(&m->user_reply, pair);
			auth_format_msg(m, MSG_PASSWORD_EXPIRE_WARNING);
		}
		break;
		
	case auth_reject:
		if (is_log_mode(m, RLOG_AUTH)) 
			auth_log(m, _("Rejected"),
				 NULL, NULL, NULL);  
		newstate(as_reject);
		auth_format_msg(m, MSG_ACCESS_DENIED);
		break;

	case auth_ignore:
		if (is_log_mode(m, RLOG_AUTH)) 
			auth_log(m, _("Ignored"),
				 NULL, NULL, NULL);
		newstate(as_stop);
		break;
                                
	case auth_nouser:
		if (is_log_mode(m, RLOG_AUTH)) 
			auth_log(m, _("No such user"),
				 NULL, NULL, NULL);
		newstate(as_reject_cleanup);
		auth_format_msg(m, MSG_ACCESS_DENIED);
		break;
                                
	case auth_fail:
		if (is_log_mode(m, RLOG_AUTH)) 
			auth_log(m,
				 _("Login incorrect"),
				 is_log_mode(m, RLOG_FAILED_PASS) ?
				 m->userpass : NULL,
				 NULL, NULL);
		newstate(as_reject_cleanup);
		auth_format_msg(m, MSG_ACCESS_DENIED);
		break;

	case auth_account_expired:
		auth_format_msg(m, MSG_PASSWORD_EXPIRED);
                newstate(as_reject_cleanup);
                if (is_log_mode(m, RLOG_AUTH)) {
                        auth_log(m,
                                 _("Login incorrect"),
				 NULL,
                                 _("Account expired"), NULL);
                }
		break;
		
	case auth_password_expired:
		auth_format_msg(m, MSG_PASSWORD_EXPIRED);
                newstate(as_reject_cleanup);
                if (is_log_mode(m, RLOG_AUTH)) {
                        auth_log(m,
                                 _("Login incorrect"),
				 NULL,
                                 _("Password expired"), NULL);
                }
		break;

	default:
		grad_insist_fail("sfn_validate");
	}
	return;
}

void
sfn_disable(AUTH_MACH *m)
{
        if (get_deny(m->namepair->avp_strvalue)) {
                auth_format_msg(m, MSG_ACCOUNT_CLOSED);
                auth_log(m, _("Account disabled"), NULL, NULL, NULL);
                newstate(as_reject_cleanup);
        }
}

void
sfn_realmuse(AUTH_MACH *m)
{
        if (!m->req->realm)
                return;
        
        if (radius_mlc_realm(m->req) == 0)
                return;
        auth_format_msg(m, MSG_REALM_QUOTA);
        auth_log(m, _("Login failed"), NULL,
                 _("realm quota exceeded for "), m->req->realm->realm);
        newstate(as_reject_cleanup);
}

void
sfn_simuse(AUTH_MACH *m)
{
        char  name[GRAD_STRING_LENGTH];
        int rc;
        int count;
	
        strip_username(strip_names,
                       m->namepair->avp_strvalue, m->user_check, name);
        rc = radius_mlc_user(name, m->req,
                             m->check_pair->avp_lvalue, &count);
        grad_avl_add_pair(&m->user_reply,
			  grad_avp_create_integer(DA_SIMULTANEOUS_USE, count));
        if (!rc)
                return;

        auth_format_msg(m,
                        (m->check_pair->avp_lvalue > 1) ?
                        MSG_MULTIPLE_LOGIN : MSG_SECOND_LOGIN);

        grad_log_req(GRAD_LOG_WARN, m->req->request,
		     _("Multiple logins: [%s] max. %ld%s"),
		     m->namepair->avp_strvalue,
		     m->check_pair->avp_lvalue,
		     rc == 2 ? _(" [MPP attempt]") : "");
        newstate(as_reject_cleanup);
}

static grad_uint32_t
set_session_timeout(AUTH_MACH *m, grad_uint32_t val)
{
	grad_avp_t *p;
	
        if (!(p = grad_avl_find(m->user_reply, DA_SESSION_TIMEOUT))) {
                p = grad_avp_create_integer(DA_SESSION_TIMEOUT, val);
                grad_avl_add_pair(&m->user_reply, p);
        } else if (p->avp_lvalue > val)
		p->avp_lvalue = val;
        return p->avp_lvalue;
}

void
sfn_time(AUTH_MACH *m)
{
        int rc;
        time_t t;
        unsigned rest;
        
        time(&t);
        rc = ts_check(m->check_pair->avp_strvalue, &t, &rest, NULL);
        if (rc == 1) {
                /*
                 * User called outside allowed time interval.
                 */
                auth_format_msg(m, MSG_TIMESPAN_VIOLATION);
                grad_log_req(GRAD_LOG_ERR,
			     m->req->request,
			     _("Outside allowed timespan (%s)"),
			     m->check_pair->avp_strvalue);
                newstate(as_reject_cleanup);
        } else if (rc == 0) {
                /*
                 * User is allowed, but set Session-Timeout.
                 */
                grad_uint32_t to = set_session_timeout(m, rest);
                GRAD_DEBUG4(2, "user %s, span %s, timeout %d, real timeout %d",
                            m->namepair->avp_strvalue,
                            m->check_pair->avp_strvalue,
                            rest,
			    to);
        }
}

void
sfn_ipaddr(AUTH_MACH *m)
{
        grad_avp_t *p, *tmp, *pp;
        
        /* Assign an IP if necessary */
        if (!grad_avl_find(m->user_reply, DA_FRAMED_IP_ADDRESS)) {
                if (p = grad_avl_find(m->req->request->avlist,
				      DA_FRAMED_IP_ADDRESS)) {
                        /* termserver hint */
                        grad_avl_add_pair(&m->user_reply, grad_avp_dup(p));
                }
        }
        
}

void
sfn_exec_wait(AUTH_MACH *m)
{
	int rc;
	grad_avp_t *p;
	grad_avp_t *reply = NULL;

	rc = exec_program_wait (m->req, m->check_pair, &reply, &p);
	
	if (rc != 0) {
		newstate(as_reject);

		if (is_log_mode(m, RLOG_AUTH)) {
			auth_log(m, _("Login incorrect"),
				 NULL,
				 _("external check failed: "), 
				 p->avp_strvalue);
		}

		grad_avl_free(m->user_reply);
		m->user_reply = reply;
		if (!grad_avl_find(m->user_reply, DA_REPLY_MESSAGE))
			auth_format_msg(m, MSG_ACCESS_DENIED);
	} else {
		grad_avl_merge(&m->user_reply, &reply);
		grad_avl_free(reply);
	}
}

void
sfn_exec_nowait(AUTH_MACH *m)
{
	grad_avp_t *p;
	
	for (p = m->check_pair;
             p;
             p = grad_avl_find(p->next, DA_EXEC_PROGRAM)) {
		radius_eval_avp(m->req, p, NULL, 1);
		radius_exec_program(p->avp_strvalue, m->req, NULL, 0);
	}
}

void
sfn_cleanup_cbkid(AUTH_MACH *m)
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
                grad_avl_delete(&m->user_reply, *ip);
}

void
sfn_menu_challenge(AUTH_MACH *m)
{
#ifdef USE_LIVINGSTON_MENUS
        char *msg;
        char state_value[MAX_STATE_VALUE];
                
        msg = menu_read_text(m->check_pair->avp_strvalue);
        snprintf(state_value, sizeof(state_value),
                   "MENU=%s", m->check_pair->avp_strvalue);
        radius_send_challenge(m->req, msg, state_value, m->activefd);
        grad_free(msg);
	
        GRAD_DEBUG2(1, "sending challenge (menu %s) to %s",
                    m->check_pair->avp_strvalue, m->namepair->avp_strvalue);
        newstate(as_stop);
#endif  
}

void
sfn_ack(AUTH_MACH *m)
{
        GRAD_DEBUG1(1, "ACK: %s", m->namepair->avp_strvalue);
        
	radius_eval_avl(m->req, m->user_reply);

        radius_send_reply(RT_ACCESS_ACCEPT,
                          m->req,
                          m->user_reply,
                          auth_finish_msg(m),
                          m->activefd);
        
        if (is_log_mode(m, RLOG_AUTH)) {
                auth_log(m, _("Login OK"),
                         is_log_mode(m, RLOG_AUTH_PASS) ? m->userpass : NULL,
                         NULL, NULL);
        }
}

void
sfn_reject_cleanup(AUTH_MACH *m)
{
	grad_avl_free(m->user_reply);
	m->user_reply = NULL;
	newstate(as_reject);
}

void
sfn_reject(AUTH_MACH *m)
{
        GRAD_DEBUG1(1, "REJECT: %s", m->namepair->avp_strvalue);
	radius_eval_avl(m->req, m->user_reply);
        radius_send_reply(RT_ACCESS_REJECT,
                          m->req,
                          m->user_reply,
                          auth_finish_msg(m),
                          m->activefd);
}

void
req_decrypt_password(char *password, grad_request_t *req, grad_avp_t *pair)
{
        grad_nas_t *nas;
        char *s;
        
        if (!pair) {
                pair = grad_avl_find(req->avlist, DA_USER_PASSWORD);
                if (!pair)
                        return;
        }

	if (pair->prop & GRAD_AP_ENCRYPT_RFC2138) {
		/* Determine whether we need to use broken decoding */
		nas = grad_nas_request_to_nas(req);
		if (nas
		    && (s = grad_envar_lookup(nas->args, "broken_pass")) != NULL
		    && s[0] == '1')
			grad_decrypt_password_broken(password, pair,
						     req->authenticator,
						     req->secret);
		else
			grad_decrypt_password(password, pair,
					      req->authenticator,
					      req->secret);
	} else if (pair->prop & GRAD_AP_ENCRYPT_RFC2868) {
		u_char tag; /* FIXME: not accessible for user */
		grad_decrypt_tunnel_password(password, 
					     &tag, pair,
					     req->authenticator,
					     req->secret);
	}
}
