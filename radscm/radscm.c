/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <libguile.h>
#include <radius.h>
#include <radutmp.h>
#include <radclient.h>
#include <radscm.h>

static RADCLIENT *radclient;

static SERVER *scheme_to_server(SCM g_list, const char *func);

static void
die(msg)
	char *msg;
{
	radlog(L_ERR, "%s", msg);
}


SCM_DEFINE(rad_directory, "rad-directory", 1, 0, 0,
	   (SCM DIR),
	   "Sets radius database directory to dir")
#define FUNC_NAME s_rad_directory
{
	SCM_ASSERT(SCM_NIMP(DIR) && SCM_STRINGP(DIR),
		   DIR, SCM_ARG1, FUNC_NAME);
	radius_dir = SCM_CHARS(DIR);
	if (dict_init())
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
"PORT  NUMBER	Port to use.\n"
"			0 - Authentication port\n"
"			1 - Accounting port\n"
"			2 - Control port\n"
"		The actual port numbers are those configured for\n"
"		the given server.\n"
"CODE  NUMBER	Request code.\n"
"PAIRS LIST	List of Attribute-value pairs. Each pair is:\n"
"			(cons ATTR-NAME-STRING . VALUE)\n"
"		or\n"
"			(cons ATTR-NUMBER . VALUE)\n"
"\n"
"Return:\n"
"\n"
"On success\n"
"	(list RETURN-CODE-NUMBER PAIR-LIST)\n"
"On failure:\n"
"	'()\n")
#define FUNC_NAME s_rad_send_internal	   
{
	int port;
	int code;
	VALUE_PAIR *pairlist;
	SCM scm_auth, scm_plist;
	RADIUS_REQ *auth;
	
	SCM_ASSERT((SCM_IMP(PORT) && SCM_INUMP(PORT)),
		   PORT, SCM_ARG1, FUNC_NAME);
	port = SCM_INUM(PORT);
	SCM_ASSERT((SCM_IMP(CODE) && SCM_INUMP(CODE)),
		   CODE, SCM_ARG2, FUNC_NAME);
	code = SCM_INUM(CODE);
	SCM_ASSERT(((SCM_IMP(PAIRS) && SCM_EOL == PAIRS) ||
		    (SCM_NIMP(PAIRS) && SCM_CONSP(PAIRS))),
		   PAIRS, SCM_ARG3, FUNC_NAME);

	if (SCM_IMP(PAIRS) && SCM_EOL == PAIRS)
		pairlist = NULL;
	else
		pairlist = radscm_list_to_avl(PAIRS);

	auth = radclient_send(radclient, port, code, pairlist);
	if (!auth)
		return SCM_EOL;
	/*
	 * Construct scheme return values
	 */
	scm_auth = SCM_MAKINUM(auth->code);
	scm_plist = radscm_avl_to_list(auth->request);
	
	return scm_cons(scm_auth, scm_plist);
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_list_servers, "rad-client-list-servers", 0, 0, 0,
	   (),
"List currently configured servers. Two column for each server are displayed:\n"
"Server ID and IP address.\n")
#define FUNC_NAME s_rad_client_list_servers	   
{
	SERVER *s;
	char p[DOTTED_QUAD_LEN+1];
	SCM tail = SCM_EOL;
         
	for (s = radclient->first_server; s; s = s->next) {
		ipaddr2str(p, s->addr);
		tail = scm_cons(SCM_LIST2(scm_makfrom0str(s->name),
					  scm_makfrom0str(p)),
				tail);
	}
	return scm_reverse_x(tail, SCM_UNDEFINED);
}
#undef FUNC_NAME

SCM_DEFINE(rad_get_server, "rad-get-server", 0, 0, 0,
	   (),
	   "Returns the ID of the currently selected server.")
#define FUNC_NAME s_rad_get_server	
{
	return scm_makfrom0str(radclient->first_server->name);
}
#undef FUNC_NAME

SERVER *
scheme_to_server(LIST, func)
	SCM LIST;
	const char *func;
{
	SERVER serv;
	SCM scm;
	
	SCM_ASSERT((SCM_NIMP(LIST) && SCM_CONSP(LIST)),
		   LIST, SCM_ARG1, func);
	
	scm = SCM_CAR(LIST);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm),
		   scm, SCM_ARG1, func);
	serv.name = SCM_CHARS(scm);

	scm = SCM_CADR(LIST);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm),
		   scm, SCM_ARG1, func);
	serv.addr = get_ipaddr(SCM_CHARS(scm));
	if (serv.addr == 0) 
		scm_misc_error(func,
			       "Bad hostname or ip address ~S\n",
			       scm);

	scm = SCM_CADDR(LIST);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm),
		   scm, SCM_ARG1, func);
	serv.secret = SCM_CHARS(scm);

	scm = SCM_CADDDR(LIST);
	SCM_ASSERT(SCM_IMP(scm) && SCM_INUMP(scm),
		   scm, SCM_ARG1, func);
	serv.port[PORT_AUTH] = SCM_INUM(scm);
	
	scm = SCM_CAR(SCM_CDDDDR(LIST));
	SCM_ASSERT(SCM_IMP(scm) && SCM_INUMP(scm),
		   scm, SCM_ARG1, func);
	serv.port[PORT_ACCT] = SCM_INUM(scm);

	return radclient_alloc_server(&serv);
}

SCM_DEFINE(rad_client_add_server, "rad-client-add-server", 1, 0, 0,
	   (SCM LIST),
	   "Add a server to the list of configured radius servers")
#define FUNC_NAME s_rad_client_add_server
{
	radclient->first_server =
		radclient_append_server(radclient->first_server,
					scheme_to_server(LIST, FUNC_NAME));
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_set_server, "rad-client-set-server", 1, 0, 0, 
	   (SCM LIST),
"Selects for use the server described by LIST. A LIST should be:\n"
"\n"
"	(list ID-STRING HOST-STRING SECRET-STRING AUTH-NUM ACCT-NUM)\n"
"Where:\n"
"	ID-STRING	Server ID\n"
"	HOST-STRING	Server hostname or IP address\n"
"	SECRET-STRING	Shared secret key to use\n"
"	AUTH-NUM	Authentication port number\n"
"	ACCT-NUM	Accounting port number\n")
#define FUNC_NAME s_rad_client_set_server
{
	SERVER *s = scheme_to_server(LIST, FUNC_NAME);
	
	radclient_clear_server_list(radclient->first_server);
	radclient->first_server = radclient_append_server(NULL, s);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_source_ip, "rad-client-source-ip", 1, 0, 0,
	   (SCM IP),
"Set source IP address for packets coming from this client\n")
#define FUNC_NAME s_rad_client_source_ip
{
	UINT4 ip;
	
	SCM_ASSERT((SCM_NIMP(IP) && SCM_STRINGP(IP)), IP, SCM_ARG1, FUNC_NAME);
	ip = get_ipaddr(SCM_CHARS(IP));
	if (ip)
		radclient->source_ip = ip;
	else {
		scm_misc_error(FUNC_NAME,
			       "Invalid IP/hostname: ~S",
			       SCM_LIST1(IP));
	}

	return SCM_BOOL_T;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_timeout, "rad-client-timeout", 1, 0, 0,
	   (SCM TO),
"Sets the timeout for waiting for the server reply.\n")
#define FUNC_NAME s_rad_client_timeout
{
	SCM_ASSERT(SCM_IMP(TO) && SCM_INUMP(TO), TO, SCM_ARG1, FUNC_NAME);
	radclient->timeout = SCM_INUM(TO);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_retry, "rad-client-retry", 1, 0, 0,
	   (SCM RETRY),
"Sets the number of retries for sending requests to a radius server.")
#define FUNC_NAME s_rad_client_retry
{
	SCM_ASSERT(SCM_IMP(RETRY) && SCM_INUMP(RETRY),
		   RETRY, SCM_ARG1, FUNC_NAME);
	radclient->retries = SCM_INUM(RETRY);
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
	
	SCM_ASSERT((SCM_NIMP(PROMPT) && SCM_STRINGP(PROMPT)),
		   PROMPT, SCM_ARG1, FUNC_NAME);
	s = getpass(SCM_CHARS(PROMPT));
	return scm_makfrom0str(s);
}
#undef FUNC_NAME


void
rad_scheme_init(argc, argv)
	int argc;
	char **argv;
{
	int di, si;
	int double_dash = 0;
	SCM *scm_loc;
	char *bootpath;
	char *p;
	
	/*
	 * Process and throw-off radius-specific command line
	 * options.
	 */
	for (si = di = 0; si < argc; ) {
		if (double_dash) {
			argv[di++] = argv[si++];
		} else if (strcmp(argv[si], "--") == 0) {
			double_dash++;
			argv[di++] = argv[si++];
		} else if (strcmp(argv[si], "-ds") == 0) {
			/* allow for guile's -ds option */
			argv[di++] = argv[si++];
		} else if (strncmp(argv[si], "-d", 2) == 0) {
			if (argv[si][2]) {
				radius_dir = argv[si++]+2;
			} else {
				if (++si >= argc) 
					die("option requires argument: -d");
				radius_dir = argv[si++];
			}
		} else if (strcmp(argv[si], "--directory") == 0) {
			if (++si >= argc) 
				die("option requires argument: --directory");
			radius_dir = argv[si++];
		} else
			argv[di++] = argv[si++];
	}
	argv[di] = NULL;
	argc = di;
	
	/*
	 * Initialize radius sub-system
	 */
	radpath_init();
	if (dict_init()) {
		radlog(L_ERR, _("error reading dictionary file"));
		exit(1);
	}
	radclient = radclient_alloc(0, 0);

	/*
	 * Provide basic primitives
	 */

	radscm_init();
	
#include <radscm.x>

	scm_loc = SCM_CDRLOC (scm_sysintern ("%raddb-path", SCM_EOL));
	*scm_loc = scm_makfrom0str(radius_dir);

	if (!(bootpath = getenv("RADSCM_BOOTPATH")))
		bootpath = DATADIR;	
#if 0
	/*
	 * Reset %load-path
	 */
	scm = scm_cons(scm_makfrom0str(bootpath),
		       scm_symbol_value0("%load-path"));
	scm_loc = SCM_CDRLOC (scm_sysintern ("%load-path", SCM_EOL));
	*scm_loc = scm;
#endif
	/*
	 * Load radius scheme modules
	 */
	p = mkfilename(bootpath, "boot.scm");
	scm_primitive_load(scm_makfrom0str(p));
	efree(p);

	scm_shell(argc, argv);
}
