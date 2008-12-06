/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <libguile.h>

#include <common.h>
#include <radius/radutmp.h>
#include <radius/radscm.h>

static grad_server_queue_t *srv_queue;

static grad_server_t *scheme_to_server(SCM g_list, const char *func);

static void
die(char *msg)
{
        grad_log(GRAD_LOG_ERR, "%s", msg);
}

#if SCM_MAJOR_VERSION == 1 && SCM_MINOR_VERSION == 6
SCM
scm_i_make_string(size_t len, char **p)
{
  SCM ret = scm_allocate_string(len);
  *p = SCM_STRING_CHARS(ret);
  return ret;
}
#endif

SCM_DEFINE(rad_directory, "rad-directory", 1, 0, 0,
           (SCM DIR),
           "Sets radius database directory to dir")
#define FUNC_NAME s_rad_directory
{
        SCM_ASSERT(scm_is_string(DIR), DIR, SCM_ARG1, FUNC_NAME);
        /* FIXME: perhaps should allocate memory here */
        grad_config_dir = scm_i_string_chars (DIR);
        if (grad_dict_init())
                return SCM_BOOL_F;
        return SCM_BOOL_T;
}
#undef FUNC_NAME

/*
 * (define (rad-send-internal port code pairlist) ... )
 */
SCM_DEFINE(rad_send_internal, "rad-send-internal", 3, 0, 0,
           (SCM PORT, SCM CODE, SCM PAIRS),
"Sends the request to currently selected server.\n"
"PORT  NUMBER   Port to use.\n"
"                       0 - Authentication port\n"
"                       1 - Accounting port\n"
"                       2 - Control port\n"
"               The actual port numbers are those configured for\n"
"               the given server.\n"
"CODE  NUMBER   Request code.\n"
"PAIRS LIST     List of Attribute-value pairs. Each pair is:\n"
"                       (cons ATTR-NAME-STRING . VALUE)\n"
"               or\n"
"                       (cons ATTR-NUMBER . VALUE)\n"
"\n"
"Return:\n"
"\n"
"On success\n"
"       (list RETURN-CODE-NUMBER PAIR-LIST)\n"
"On failure:\n"
"       '()\n")
#define FUNC_NAME s_rad_send_internal      
{
        int port;
        int code;
        grad_avp_t *pairlist;
        SCM scm_auth, scm_plist;
        grad_request_t *auth;
        
        SCM_ASSERT(scm_is_integer(PORT), PORT, SCM_ARG1, FUNC_NAME);
        port = scm_to_int(PORT);
        SCM_ASSERT(scm_is_integer(CODE), CODE, SCM_ARG2, FUNC_NAME);
        code = scm_to_int(CODE);
        SCM_ASSERT(((SCM_IMP(PAIRS) && SCM_EOL == PAIRS) ||
                    (SCM_NIMP(PAIRS) && SCM_CONSP(PAIRS))),
                   PAIRS, SCM_ARG3, FUNC_NAME);

        if (SCM_IMP(PAIRS) && SCM_EOL == PAIRS)
                pairlist = NULL;
        else
                pairlist = radscm_list_to_avl(PAIRS);

        auth = grad_client_send(srv_queue, port, code, pairlist);
        if (!auth)
                return SCM_EOL;
        /*
         * Construct scheme return values
         */
        scm_auth = scm_from_int(auth->code);
        scm_plist = radscm_avl_to_list(auth->avlist);
        
        return scm_cons(scm_auth, scm_plist);
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_list_servers, "rad-client-list-servers", 0, 0, 0,
           (),
"List currently configured servers. Two column for each server are displayed:\n"
"Server ID and IP address.\n")
#define FUNC_NAME s_rad_client_list_servers        
{
        grad_server_t *s;
        char p[GRAD_IPV4_STRING_LENGTH+1];
        SCM tail = SCM_EOL;
        grad_iterator_t *itr = grad_iterator_create(srv_queue->servers);

        for (s = grad_iterator_first(itr); s; s = grad_iterator_next(itr)) {
                grad_ip_iptostr(s->addr, p);
                tail = scm_cons(scm_list_2(scm_makfrom0str(s->name),
                                          scm_makfrom0str(p)),
                                tail);
        }
        grad_iterator_destroy(&itr);
        return scm_reverse_x(tail, SCM_UNDEFINED);
}
#undef FUNC_NAME

SCM_DEFINE(rad_get_server, "rad-get-server", 0, 0, 0,
           (),
           "Returns the ID of the currently selected server.")
#define FUNC_NAME s_rad_get_server      
{
	/*FIXME*/
	grad_server_t *s = grad_list_item(srv_queue->servers, 0);
	return s ? scm_makfrom0str(s->name) : SCM_BOOL_F;
}
#undef FUNC_NAME

grad_server_t *
scheme_to_server(SRVLIST, func)
        SCM SRVLIST;
        const char *func;
{
        grad_server_t serv;
        SCM scm;
        
        SCM_ASSERT((SCM_NIMP(SRVLIST) && SCM_CONSP(SRVLIST)),
                   SRVLIST, SCM_ARG1, func);
        
        scm = SCM_CAR(SRVLIST);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
        /* FIXME: alloc memory here */
        serv.name = scm_i_string_chars(scm); 

        scm = SCM_CADR(SRVLIST);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
        serv.addr = grad_ip_gethostaddr(scm_i_string_chars(scm));
        if (serv.addr == 0) 
                scm_misc_error(func,
                               "Bad hostname or ip address ~S\n",
                               scm);

        scm = SCM_CADDR(SRVLIST);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
        /* FIXME: alloc memory here */
        serv.secret = scm_i_string_chars(scm);

        scm = SCM_CADDDR(SRVLIST);
        SCM_ASSERT(scm_is_integer(scm), scm, SCM_ARG1, func);
        serv.port[GRAD_PORT_AUTH] = scm_to_int(scm);
        
        scm = SCM_CAR(SCM_CDDDDR(SRVLIST));
        SCM_ASSERT(scm_is_integer(scm), scm, SCM_ARG1, func);
        serv.port[GRAD_PORT_ACCT] = scm_to_int(scm);

        return grad_client_alloc_server(&serv);
}

SCM_DEFINE(rad_client_add_server, "rad-client-add-server", 1, 0, 0,
           (SCM SRVLIST),
           "Add a server to the list of configured radius servers")
#define FUNC_NAME s_rad_client_add_server
{
	grad_client_append_server(srv_queue, scheme_to_server(SRVLIST, FUNC_NAME));
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_set_server, "rad-client-set-server", 1, 0, 0, 
           (SCM SRVLIST),
"Selects for use the server described by SRVLIST. A SRVLIST should be:\n"
"\n"
"       (list ID-STRING HOST-STRING SECRET-STRING AUTH-NUM ACCT-NUM)\n"
"Where:\n"
"       ID-STRING       Server ID\n"
"       HOST-STRING     Server hostname or IP address\n"
"       SECRET-STRING   Shared secret key to use\n"
"       AUTH-NUM        Authentication port number\n"
"       ACCT-NUM        Accounting port number\n")
#define FUNC_NAME s_rad_client_set_server
{
        grad_server_t *s = scheme_to_server(SRVLIST, FUNC_NAME);
        
        grad_client_clear_server_list(srv_queue);
        grad_client_append_server(srv_queue, s);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_source_ip, "rad-client-source-ip", 1, 0, 0,
           (SCM IP),
"Set source IP address for packets coming from this client\n")
#define FUNC_NAME s_rad_client_source_ip
{
        grad_uint32_t ip;
        
        SCM_ASSERT(scm_is_string(IP), IP, SCM_ARG1, FUNC_NAME);
        ip = grad_ip_gethostaddr(scm_i_string_chars(IP));
        if (ip)
                srv_queue->source_ip = ip;
        else {
                scm_misc_error(FUNC_NAME,
                               "Invalid IP/hostname: ~S",
                               scm_list_1(IP));
        }

        return SCM_BOOL_T;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_timeout, "rad-client-timeout", 1, 0, 0,
           (SCM TO),
"Sets the timeout for waiting for the server reply.\n")
#define FUNC_NAME s_rad_client_timeout
{
        SCM_ASSERT(scm_is_integer(TO), TO, SCM_ARG1, FUNC_NAME);
        srv_queue->timeout = scm_to_ulong(TO);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_retry, "rad-client-retry", 1, 0, 0,
           (SCM RETRY),
"Sets the number of retries for sending requests to a radius server.")
#define FUNC_NAME s_rad_client_retry
{
        SCM_ASSERT(scm_is_integer(RETRY), RETRY, SCM_ARG1, FUNC_NAME);
        srv_queue->retries = scm_to_uint(RETRY);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM_DEFINE(rad_read_no_echo, "rad-read-no-echo", 1, 0, 0,
           (SCM PROMPT),
"Prints the given PROMPT-STRING, disables echoing, reads a string up to the\n"
"next newline character, restores echoing and returns the string entered.\n"
"This is the interface to the C getpass(3) function.\n")
#define FUNC_NAME s_rad_read_no_echo       
{
        char *s;
        
        SCM_ASSERT(scm_is_string(PROMPT), PROMPT, SCM_ARG1, FUNC_NAME);
        s = getpass(scm_i_string_chars(PROMPT));
        return scm_makfrom0str(s);
}
#undef FUNC_NAME

SCM _rad_scm_package_string; /* STRING: PACKAGE_STRING */
SCM _rad_scm_package;        /* STRING: PACKAGE */
SCM _rad_scm_version;        /* STRING: VERSION */

/* Initialize the library */
void
radscm_init()
{
        SCM *scm_loc;
        char *bootpath;
        char *p;
        
	_rad_scm_package = scm_makfrom0str (PACKAGE);
	scm_c_define("grad-package", _rad_scm_package);
	
	_rad_scm_version = scm_makfrom0str (VERSION);
	scm_c_define("grad-version", _rad_scm_version);
	
	_rad_scm_package_string = scm_makfrom0str (PACKAGE_STRING);
	scm_c_define("grad-package-string", _rad_scm_package_string);
	
        /*
         * Initialize radius sub-system
         */
        grad_path_init();
        if (grad_dict_init()) {
                grad_log(GRAD_LOG_ERR, _("error reading dictionary file"));
                exit(1);
        }
        srv_queue = grad_client_create_queue(1, 0, 0);

        /*
         * Provide basic primitives
         */

        grad_scm_init();
        
#include <radscm.x>

        scm_c_define ("%raddb-path", scm_makfrom0str(grad_config_dir));
}

