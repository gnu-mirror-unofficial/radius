/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007, 2008, 2010
   Free Software Foundation, Inc.

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

SCM_DEFINE_PUBLIC(rad_directory, "rad-directory", 1, 0, 0,
		  (SCM dir),
"Sets radius database directory to @var{dir}")
#define FUNC_NAME s_rad_directory
{
        SCM_ASSERT(scm_is_string(dir), dir, SCM_ARG1, FUNC_NAME);
        grad_config_dir = scm_to_locale_string(dir);
        if (grad_dict_init())
                return SCM_BOOL_F;
        return SCM_BOOL_T;
}
#undef FUNC_NAME

/*
 * (define (rad-send-internal port code pairlist) ... )
 */
SCM_DEFINE_PUBLIC(rad_send_internal, "rad-send-internal", 3, 0, 0,
		  (SCM port, SCM code, SCM pairs),
"Sends request to the currently selected server.\n"
"Arguments:\n"
"@table @var\n"		  
"@item port\n"
"Port to use.  Allowed values: @samp{0}, for authentication port, "
"@samp{1}, for accounting port, and @samp{2}, for control port.\n"
"\n"		  
"Actual port numbers are those configured for the given server.\n"
"@item code\n"
"Numeric request code.\n"
"@item pairs\n"
"A list of attribute-value pairs. Each pair is: "
"@code{(cons @var{attr-name-string} @var{value})} or "
"@code{(cons @var{attr-number} @var{value})}.\n"
"@end table\n\n"
"On success, returns @code{(list @var{return-code-number} @var{pair-list})}.\n"
"On failure returns @code{'()}.\n")
#define FUNC_NAME s_rad_send_internal      
{
        int n_port;
        int n_code;
        grad_avp_t *pairlist;
        SCM scm_auth, scm_plist;
        grad_request_t *auth;
        
        SCM_ASSERT(scm_is_integer(port), port, SCM_ARG1, FUNC_NAME);
        n_port = scm_to_int(port);
        SCM_ASSERT(scm_is_integer(code), code, SCM_ARG2, FUNC_NAME);
        n_code = scm_to_int(code);
	if (scm_is_null(pairs))
		pairlist = NULL;
	else {
		SCM_ASSERT(scm_is_pair(pairs), pairs, SCM_ARG3, FUNC_NAME);
                pairlist = radscm_list_to_avl(pairs);
	}
	
        auth = grad_client_send(srv_queue, n_port, n_code, pairlist);
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

SCM_DEFINE_PUBLIC(rad_client_list_servers, "rad-client-list-servers", 0, 0, 0,
		  (),
"Returns a list of currently configured servers.  Each element is a cons: "
"@code{(@var{server-id} . @var{server-IP})}.\n")
#define FUNC_NAME s_rad_client_list_servers        
{
        grad_server_t *s;
        char p[GRAD_IPV4_STRING_LENGTH+1];
        SCM tail = SCM_EOL;
        grad_iterator_t *itr = grad_iterator_create(srv_queue->servers);

        for (s = grad_iterator_first(itr); s; s = grad_iterator_next(itr)) {
                grad_ip_iptostr(s->addr, p);
                tail = scm_cons(scm_list_2(scm_from_locale_string(s->name),
					   scm_from_locale_string(p)),
                                tail);
        }
        grad_iterator_destroy(&itr);
        return scm_reverse_x(tail, SCM_UNDEFINED);
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_get_server, "rad-get-server", 0, 0, 0,
		  (),
"Returns ID of the currently selected server.")
#define FUNC_NAME s_rad_get_server      
{
	/*FIXME*/
	grad_server_t *s = grad_list_item(srv_queue->servers, 0);
	return s ? scm_from_locale_string(s->name) : SCM_BOOL_F;
}
#undef FUNC_NAME

grad_server_t *
scheme_to_server(SCM srvlist, const char *func)
{
        grad_server_t serv;
        SCM scm;
        char *p;
	
        SCM_ASSERT(scm_is_pair(srvlist), srvlist, SCM_ARG1, func);
        
        scm = SCM_CAR(srvlist);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
	serv.name = scm_to_locale_string(scm); 

        scm = SCM_CADR(srvlist);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
	p = scm_to_locale_string(scm);
        serv.addr = grad_ip_gethostaddr(p);
	free(p);
        if (serv.addr == 0) 
                scm_misc_error(func,
                               "Bad hostname or ip address ~S\n",
                               scm);

        scm = SCM_CADDR(srvlist);
        SCM_ASSERT(scm_is_string(scm), scm, SCM_ARG1, func);
        serv.secret = scm_to_locale_string(scm);

        scm = SCM_CADDDR(srvlist);
        SCM_ASSERT(scm_is_integer(scm), scm, SCM_ARG1, func);
        serv.port[GRAD_PORT_AUTH] = scm_to_int(scm);
        
        scm = SCM_CAR(SCM_CDDDDR(srvlist));
        SCM_ASSERT(scm_is_integer(scm), scm, SCM_ARG1, func);
        serv.port[GRAD_PORT_ACCT] = scm_to_int(scm);

        return grad_client_alloc_server(&serv);
}

SCM_DEFINE_PUBLIC(rad_client_add_server, "rad-client-add-server", 1, 0, 0,
		  (SCM srvlist),
"Adds a server described by @var{srvlist} to the list of configured radius servers")
#define FUNC_NAME s_rad_client_add_server
{
	grad_client_append_server(srv_queue,
				  scheme_to_server(srvlist, FUNC_NAME));
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_client_set_server, "rad-client-set-server", 1, 0, 0, 
		  (SCM srv),
"Selects the server described by @var{srv}, which is a list: "
"@lisp\n"
"(list @var{id-string} @var{host-string} @var{secret-string} @var{auth-num} @var{acct-num})\n"
"@end lisp\n"
"@noindent\n"		  
"Where:\n"
"@table @var\n"		  
"@item id-string\n"
"Server ID.\n"
"@item @var{host-string}\n"
"Server hostname or IP address.\n"
"@item secret-string\n"
"Shared secret key.\n"
"@item auth-num\n"
"Authentication port number.\n"
"@item acct-num\n"
"Accounting port number.\n"
"@end table\n")
#define FUNC_NAME s_rad_client_set_server
{
        grad_server_t *s = scheme_to_server(srv, FUNC_NAME);
        
        grad_client_clear_server_list(srv_queue);
        grad_client_append_server(srv_queue, s);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_client_source_ip, "rad-client-source-ip", 1, 0, 0,
		  (SCM ipaddr),
"Sets source IP address for outgoing RADIUS packets.\n")
#define FUNC_NAME s_rad_client_source_ip
{
        grad_uint32_t ip;
        char *str;
	
        SCM_ASSERT(scm_is_string(ipaddr), ipaddr, SCM_ARG1, FUNC_NAME);
	str = scm_to_locale_string(ipaddr);
        ip = grad_ip_gethostaddr(str);
	free(str);
        if (ip)
                srv_queue->source_ip = ip;
        else {
                scm_misc_error(FUNC_NAME,
                               "Invalid IP/hostname: ~S",
                               scm_list_1(ipaddr));
        }

        return SCM_BOOL_T;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_client_timeout, "rad-client-timeout", 1, 0, 0,
		  (SCM to),
"Sets timeout for waiting for the reply.\n")
#define FUNC_NAME s_rad_client_timeout
{
        SCM_ASSERT(scm_is_integer(to), to, SCM_ARG1, FUNC_NAME);
        srv_queue->timeout = scm_to_ulong(to);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_client_retry, "rad-client-retry", 1, 0, 0,
		  (SCM retry),
"Sets number of retries for sending requests to a radius server.")
#define FUNC_NAME s_rad_client_retry
{
        SCM_ASSERT(scm_is_integer(retry), retry, SCM_ARG1, FUNC_NAME);
        srv_queue->retries = scm_to_uint(retry);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM_DEFINE_PUBLIC(rad_read_no_echo, "rad-read-no-echo", 1, 0, 0,
		  (SCM prompt),
"Prints the given prompt string @var{prompt}, disables echoing, "
"reads a string up to the next newline character, restores echoing "
"and returns the obtained string.\n"
"This is an interface to the C getpass(3) function.\n")
#define FUNC_NAME s_rad_read_no_echo       
{
        char *s;
        char *prompt_str;
	
        SCM_ASSERT(scm_is_string(prompt), prompt, SCM_ARG1, FUNC_NAME);
	prompt_str = scm_to_locale_string(prompt);
        s = getpass(prompt_str);
	free(prompt_str);
        return scm_from_locale_string(s);
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
        
	_rad_scm_package = scm_from_locale_string (PACKAGE);
	scm_c_define("grad-package", _rad_scm_package);

	_rad_scm_version = scm_from_locale_string (VERSION);
	scm_c_define("grad-version", _rad_scm_version);

	_rad_scm_package_string = scm_from_locale_string (PACKAGE_STRING);
	scm_c_define("grad-package-string", _rad_scm_package_string);
	
	scm_c_export("grad-package", "grad-version", "grad-package-string",
		     NULL);
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

        scm_c_define ("%raddb-path", scm_from_locale_string(grad_config_dir));
	scm_c_export ("%raddb-path", NULL);
}

