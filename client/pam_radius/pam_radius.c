/* This file is part of GNU RADIUS.
   Copyright (C) 2001 Sergey Poznyakoff
 
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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#ifdef HAVE__PAM_ACONF_H
#include <security/_pam_aconf.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>

#include <radius.h> 
#include <radpaths.h> 

/* indicate the following groups are defined */
#define PAM_SM_AUTH

#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif                          /* LINUX_PAM */
#include <security/pam_modules.h>

#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif
#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define PAM_OVERWRITE(s)        \
  do {                           \
        register char *p;        \
        if  ((p = s) != NULL)    \
            while (*p) *p++ = 0; \
  } while (0) 

#define PAM_DROP_REPLY(reply, nrepl)                 \
  do {                                                \
        int i;                                        \
        for (i=0; i<nrepl; i++) {                     \
            PAM_OVERWRITE(reply[i].resp);             \
            free(reply[i].resp);                      \
        }                                             \
        if (reply)                                    \
            free(reply);                              \
  } while (0)
        
static void
_pam_delete(char *x)
{
        PAM_OVERWRITE(x);
        free(x);
}

static void
_cleanup_string(pam_handle_t *pamh, void *x, int error_status)
{
        _pam_delete(x);
}

/* Clean up the temporary A/V pair list */
static void
_cleanup_fake_pairlist(VALUE_PAIR *p)
{
	VALUE_PAIR *next;
	while (p) {
		next = p->next;
		mem_free(p);
		p = next;
	}
}

static void
_cleanup_pairlist(pam_handle_t *pamh, void *x, int error_status)
{
	_cleanup_fake_pairlist(x); 
}

/* logging */
static void
_pam_vlog(int err, const char *format, va_list args)
{
        openlog("pam_radius", LOG_CONS|LOG_PID, LOG_AUTH);
        vsyslog(err, format, args);
        closelog();
}

static void
_pam_log 
#if STDC_HEADERS
        (int err, const char *format, ...)
#else
        (err, format, va_alist)
        int err;
        const char *format;
        va_dcl
#endif
{
        va_list args;

#if STDC_HEADERS
        va_start(args, format);
#else
	va_start(args);
#endif
        _pam_vlog(err, format, args);
        va_end(args);
}

static void
_pam_debug
#if STDC_HEADERS
          (char *format, ...)
#else
          (format, va_alist)
        char *format;
        va_dcl
#endif
{
        va_list args;

#if STDC_HEADERS
	va_start(args, format);
#else
        va_start(args);
#endif
        _pam_vlog(LOG_DEBUG, format, args);
        va_end(args);
}


/* Maps radius priorities into syslog ones */
int priority[] = {
        LOG_EMERG,
        LOG_ALERT,
        LOG_CRIT,
        LOG_ERR,
        LOG_WARNING,
        LOG_NOTICE,
        LOG_INFO,
        LOG_DEBUG
};


void
vlog(level, file, line, func_name, en, fmt, ap)
        int level;
        char *file;
        int line;
        char *func_name;
        int en;
        char *fmt;
        va_list ap;
{
        openlog("pam_radius", LOG_CONS|LOG_PID, LOG_AUTH);
        vsyslog(priority[level & L_PRIMASK], fmt, ap);
        if (en)
                syslog(priority[L_MASK(level)], "syserr: %s (%d)",
                       strerror(en), en);
        closelog();
}



#define CNTL_DEBUG       0x0001
#define CNTL_AUDIT       0x0002
#define CNTL_AUTHTOK     0x0004
#define CNTL_WAITDEBUG   0x0008

#define CNTL_DEBUG_LEV() (cntl_flags>>16)
#define CNTL_SET_DEBUG_LEV(cntl,n) (cntl |= ((n)<<16))

static int cntl_flags;
static char *radius_confdir = RADDB_DIR;
static char *service_type = NULL;

#define DEBUG(m,c) if (CNTL_DEBUG_LEV()>=(m)) _pam_debug c
#define AUDIT(c) if (cntl_flags&CNTL_AUDIT) _pam_debug c

#define XSTRDUP(s) (s) ? strdup(s) : NULL

static void
make_str(pam_handle_t *pamh, const char *str, const char *name, char **ret)
{
        int retval;
        char *newstr = XSTRDUP(str);

        retval = pam_set_data(pamh, name, (void *)newstr, _cleanup_string);
        if (retval != PAM_SUCCESS) {
                _pam_log(LOG_CRIT, 
                         "can't keep data [%s]: %s",
                         name,
                         pam_strerror(pamh, retval));
                _pam_delete(newstr);
        } else {
                *ret = newstr;
                newstr = NULL;
        }
}

#define MAKE_STR(pamh, str, var) \
 make_str(pamh,str,#var,&var)
        
static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
        int ctrl=0;
	int in_attr = 0;
	VALUE_PAIR *head = NULL, *tail = NULL;
	
        /* step through arguments */
        for (ctrl=0; argc-- > 0; ++argv) {
		
		if (in_attr) {
			char *p = strchr(*argv, '=');
			VALUE_PAIR *pair;
			
			if (!p) {
				_pam_log(LOG_ERR,
					 "pam_parse: error near %s", *argv);
				continue;
			}
			*p++ = 0;
			
			pair = mem_alloc(sizeof(*pair));
			pair->next = NULL;
			pair->name = (char *) *argv;
			pair->avp_strvalue = p;
			if (tail)
				tail->next = pair;
			else
				head = pair;
			tail = pair;
		}

		else if (!strcmp(*argv,"attr:"))
			in_attr = 1;
		
                /* generic options */

                else if (!strncmp(*argv,"debug",5)) {
                        ctrl |= CNTL_DEBUG;
                        if ((*argv)[5] == '=') 
                                CNTL_SET_DEBUG_LEV(ctrl,atoi(*argv+6));
                        else
                                CNTL_SET_DEBUG_LEV(ctrl,1);
                } else if (!strcmp(*argv,"audit"))
                        ctrl |= CNTL_AUDIT;
                else if (!strcmp(*argv,"waitdebug"))
                        ctrl |= CNTL_WAITDEBUG;
                else if (!strcmp(*argv,"use_authtok"))
                        ctrl |= CNTL_AUTHTOK;
                else if (!strncmp(*argv,"confdir=",8)) 
                        MAKE_STR(pamh, *argv+8, radius_confdir);
                else if (!strncmp(*argv,"service_type=",13)) 
                        MAKE_STR(pamh, *argv+13, service_type);
                else {
                        _pam_log(LOG_ERR,"pam_parse: unknown option; %s",
				 *argv);
                }
        }

	if (head) {
		int retval = pam_set_data(pamh, "radius_pairlist",
					  head, _cleanup_pairlist);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_CRIT, 
				 "can't keep data [%s]: %s",
				 "radius_pairlist",
				 pam_strerror(pamh, retval));
			_cleanup_fake_pairlist(head);
		}
	}
        cntl_flags = ctrl;
}

static void
_cleanup_server_queue(pam_handle_t *pamh, void *x, int error_status)
{
        rad_clt_destroy_queue(x);
}

static void
_cleanup_request(pam_handle_t *pamh, void *x, int error_status)
{
        radreq_free((RADIUS_REQ*)x);
}

#define TOK_SOURCE_IP  1
#define TOK_SERVER     2
#define TOK_SECRET     3 
#define TOK_TIMEOUT    4 
#define TOK_RETRY      5

int
_read_client_config(pam_handle_t *pamh)
{
        int errcnt = 0;
        RADIUS_SERVER_QUEUE *queue;
        
        queue = rad_clt_create_queue(1, 0, 0);
        if (!queue)
                return -1;
        /*
         * Consistency check
         */
        if (queue->first_server == NULL) {
                _pam_log(LOG_ERR, "config: no server selected");
                errcnt++;
        }

        if (queue->timeout == 0) {
                _pam_log(LOG_ERR, "config: zero timeout value");
                errcnt++;
        }

        if (errcnt) {
                /* free allocated memory */
                rad_clt_destroy_queue(queue);
        } else {
                errcnt = pam_set_data(pamh,
                                      "radius_server_queue", 
                                      (void *)queue,
                                      _cleanup_server_queue);
                if (errcnt != PAM_SUCCESS) {
                        _pam_log(LOG_CRIT, 
                                 "can't keep data [%s]: %s",
                                 "radius_server_queue",
                                 pam_strerror(pamh, errcnt));
                        rad_clt_destroy_queue(queue);
                        errcnt = 1;
                }
        }
        return errcnt;
}

static int
_pam_init_radius_client(pam_handle_t *pamh)
{
        int rc = 0;
        
        DEBUG(100,("enter _pam_init_radius_client"));

        radius_dir = radius_confdir;
        radpath_init();
        if (dict_init()) {
                _pam_log(LOG_CRIT,
                         "dict_init failed");
                return 1;
        }
        rc = _read_client_config(pamh);
        
        DEBUG(100,("exit _pam_init_radius_client"));
        return rc;
}


static int
_radius_auth(pam_handle_t *pamh, char *name, char *password)
{
        RADIUS_SERVER_QUEUE *queue;
        int retval;
        VALUE_PAIR *pairs, *namepair, *add_pair = NULL;
        RADIUS_REQ *authreq;
        DICT_VALUE *dv;
        
        retval = pam_get_data(pamh,
                              "radius_server_queue", 
                              (const void **)&queue);
        if (retval != PAM_SUCCESS) {
                _pam_log(LOG_CRIT, 
                         "can't get [radius_server_queue]: %s",
                         pam_strerror(pamh, retval));
                return PAM_AUTHINFO_UNAVAIL;
        }
        retval = pam_get_data(pamh,
                              "radius_pairlist", 
                              (const void **)&add_pair);
        if (retval != PAM_SUCCESS && retval != PAM_NO_MODULE_DATA) {
                _pam_log(LOG_CRIT, 
                         "can't get [radius_attrlist]: %s",
                         pam_strerror(pamh, retval));
                return PAM_AUTHINFO_UNAVAIL;
        }
        /*
         * Create authentication request
         */
        pairs = NULL;
        avl_add_pair(&pairs,
		     namepair = avp_create(DA_USER_NAME,
					   strlen(name), name, 0));
        avl_add_pair(&pairs, avp_create(DA_USER_PASSWORD, strlen(password),
					password, 0));
        avl_add_pair(&pairs, avp_create(DA_NAS_IP_ADDRESS,
					0, NULL,
					queue->source_ip));
	/* Add any additional attributes */
	for (; add_pair; add_pair = add_pair->next) {
		VALUE_PAIR *p = install_pair(__FILE__, __LINE__,
                                             add_pair->name, 
                                             OPERATOR_EQUAL,
				             add_pair->avp_strvalue);
		avl_add_pair(&pairs, p);
	}
	/* For compatibility with previous versions handle service_type */
        if (service_type &&
            (dv = value_name_to_value(service_type, DA_SERVICE_TYPE))) {
                DEBUG(10, ("adding Service-Type=%d", dv->value));
                avl_add_pair(&pairs,
			     avp_create(DA_SERVICE_TYPE,
					0, NULL, dv->value));
        }
        authreq = rad_clt_send(queue,
			       PORT_AUTH, RT_AUTHENTICATION_REQUEST, pairs);
        if (authreq == NULL) {
                _pam_log(LOG_ERR,
                         "no response from radius server");
                avl_free(pairs);
                return PAM_AUTHINFO_UNAVAIL;
        }

        switch (authreq->code) {
        case RT_AUTHENTICATION_ACK:
                break;
        case RT_AUTHENTICATION_REJECT:
                /* FIXME: radius may have returned Reply-Message attribute.
                 * we should return it to the caller
                 */
                radreq_free(authreq);
                return PAM_USER_UNKNOWN;
        default:
                _pam_log(LOG_CRIT,
                         "received unexpected response: %d", authreq->code);
                radreq_free(authreq);
                return PAM_AUTH_ERR;
        }

        /*
         * authentity acknowledged.
         * Preserve returned attributes;
         */
        retval = pam_set_data(pamh, "authreq",
                              (void *)authreq,
                              _cleanup_request);
        if (retval != PAM_SUCCESS) {
                _pam_log(LOG_CRIT, 
                         "can't keep data authreq: %s",
                         pam_strerror(pamh, retval));
                radreq_free(authreq);
        }
        /* add username to the response (do we need it still?) */
        avl_add_pair(&authreq->request, avp_dup(namepair));

        return PAM_SUCCESS;
}

static int
converse(pam_handle_t *pamh,
         int nargs,
         struct pam_message **message,
         struct pam_response **response)
{
        int retval;
        struct pam_conv *conv;

        DEBUG(100,("enter converse"));

        retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
        DEBUG(10,("pam_get_item(PAM_CONV): %d", retval));
        if (retval == PAM_SUCCESS) {

                retval = conv->conv(nargs,
                                    (const struct pam_message **) message,
                                    response,
                                    conv->appdata_ptr);
                
                DEBUG(10, ("app conversation returned %d", retval));

                if (retval != PAM_SUCCESS) {
                        AUDIT(("conversation failure [%s]",
                                        pam_strerror(pamh, retval)));
                }
        } else if (retval != PAM_CONV_AGAIN) {
                _pam_log(LOG_ERR, 
                         "couldn't obtain coversation function: %s",
                         pam_strerror(pamh, retval));
        }

        DEBUG(100,("exit converse: %d", retval));

        return retval;          /* propagate error status */
}

static int
_pam_get_password(pam_handle_t *pamh, char **password, const char *prompt)
{
        char *item, *token;
        int retval;
        struct pam_message msg[3], *pmsg[3];
        struct pam_response *resp;
        int i, replies;

        DEBUG(100,("enter _pam_get_password"));
        if (cntl_flags&CNTL_AUTHTOK) {
                /*
                 * get the password from the PAM item
                 */
                retval = pam_get_item(pamh, PAM_AUTHTOK,
                                      (const void **) &item);
                if (retval != PAM_SUCCESS) {
                        /* very strange. */
                        _pam_log(LOG_ALERT,
                                 "can't retrieve password item: %s",
                                 pam_strerror(pamh, retval));
                        return retval;
                } else if (item != NULL) {
                        *password = item;
                        item = NULL;
                        return PAM_SUCCESS;
                } else
                        return PAM_AUTHTOK_RECOVER_ERR;
        }

        /*
         * ask user for the password
         */
        /* prepare to converse */

        i = 0;
        pmsg[i] = &msg[i];
        msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
        msg[i++].msg = (const void*)prompt;
        replies = 1;

        /* run conversation */
        resp = NULL;
        token = NULL;
        retval = converse(pamh, i, pmsg, &resp);

        if (resp != NULL) {
                if (retval == PAM_SUCCESS) {    /* a good conversation */
                        token = XSTRDUP(resp[i - replies].resp);
                        DEBUG(10,("app returned [%s]", token));
                        PAM_DROP_REPLY(resp, 1);
                } else {
                        AUDIT(("conversation error: %s",
                                        pam_strerror(pamh, retval)));
                }
                
        } else {
                retval = (retval == PAM_SUCCESS)
                        ? PAM_AUTHTOK_RECOVER_ERR : retval;
        }

        if (retval == PAM_SUCCESS) {
                /*
                 * keep password as data specific to this module. pam_end()
                 * will arrange to clean it up.
                 */
                retval = pam_set_data(pamh, "password",
                                      (void *)token,
                                      _cleanup_string);
                if (retval != PAM_SUCCESS) {
                        _pam_log(LOG_CRIT, 
                                 "can't keep password: %s",
                                 pam_strerror(pamh, retval));
                        _pam_delete(token);
                } else {
                        *password = token;
                        token = NULL;   /* break link to password */
                }
        } else {
                AUDIT(("unable to obtain a password: %s",
                                pam_strerror(pamh, retval)));
        } 
        
        DEBUG(100,("exit _pam_get_password: %d", retval));
        return retval;
}


/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs RADIUS authentication
 *
 */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
                    int flags,
                    int argc,
                    const char **argv)
{
        int retval;
        char *name;
        char *password;

        
        _pam_parse(pamh, argc, argv);
        
#ifdef MAINTAINER_MODE
        if (cntl_flags & CNTL_WAITDEBUG) {
                _pam_log(LOG_CRIT, "WAITING FOR DEBUG AT %s:%d",
                         __FILE__, __LINE__);
                retval = 0;
                while (!retval)
                        retval=retval;
        }
#endif  
        DEBUG(100,("enter pam_sm_authenticate"));

        for (;;) {
                /*
                 * initialize client side
                 */
                if (_pam_init_radius_client(pamh)) {
                        _pam_log(LOG_ERR, "can't initialize client side");
                        retval = PAM_AUTHINFO_UNAVAIL;
                        break;
                }

                /*
                 * get username
                 */
                retval = pam_get_user(pamh, (const char**)&name, "login: ");
                if (retval == PAM_SUCCESS) {
                        DEBUG(10, ("username [%s] obtained", name));
                } else {
                        _pam_log(LOG_NOTICE, "can't get username");
                        break;
                }

                /*
                 * get password
                 */
                retval = _pam_get_password(pamh, &password,
                                           "password: ");
                
                if (retval == PAM_SUCCESS) {
                        retval = _radius_auth(pamh, name, password);
                        if (retval != PAM_SUCCESS) 
                                pam_set_item(pamh, PAM_AUTHTOK, password);
                }
                break;
        }

        name = password = NULL;
        
        DEBUG(100,("exit pam_sm_authenticate: %d", retval));
        return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh,
               int flags,
               int argc,
               const char **argv)
{
        return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_radius_modstruct = {
        "pam_radius",                      /* name of the module */
        pam_sm_authenticate,                 
        pam_sm_setcred,
        NULL,
        NULL,
        NULL,
        NULL
};

#endif

