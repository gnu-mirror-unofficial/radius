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
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <libguile.h>
#include <syslog.h>
#include <radiusd.h>
#include <radclient.h>
#include <pwd.h>

static RADCLIENT *radclient;

static SCM rad_send_internal(SCM port, SCM code, SCM pairlist);
static SCM rad_get_server();
static SCM rad_directory(SCM g_dir);
static SCM rad_client_retry(SCM);
static SCM rad_client_timeout(SCM);
static SCM rad_client_set_server(SCM);
static SCM rad_client_add_server(SCM);
static SCM rad_client_list_servers();
static SCM rad_dict_name_to_value(SCM g_attr, SCM g_value);
static SCM rad_dict_value_to_name(SCM g_attr, SCM g_value);
static SCM rad_dict_name_to_attr(SCM g_name);
static SCM rad_dict_pec_to_vendor(SCM g_pec);
static SCM rad_read_no_echo(SCM g_prompt);
static SCM rad_client_source_ip(SCM g_ip);
static SCM rad_openlog(SCM g_ident, SCM g_option, SCM g_facility);
static SCM rad_syslog(SCM g_prio, SCM g_text);
static SCM rad_closelog();

static SCM scm_makenum(unsigned long val);
static int scheme_to_pair(SCM scm, VALUE_PAIR *pair);
static VALUE_PAIR *scheme_to_list(SCM list);
static SCM list_to_scheme(VALUE_PAIR *pair);
static SERVER *scheme_to_server(SCM g_list, char *func);

static void
die(msg)
	char *msg;
{
	radlog(L_ERR, "%s", msg);
}


static struct keyword syslog_kw[] = {
	"LOG_USER",     LOG_USER,   
	"LOG_DAEMON",	LOG_DAEMON,
	"LOG_AUTH",	LOG_AUTH,  
	"LOG_LOCAL0",	LOG_LOCAL0,
	"LOG_LOCAL1",	LOG_LOCAL1,
	"LOG_LOCAL2",	LOG_LOCAL2,
	"LOG_LOCAL3",	LOG_LOCAL3,
	"LOG_LOCAL4",	LOG_LOCAL4,
	"LOG_LOCAL5",	LOG_LOCAL5,
	"LOG_LOCAL6",	LOG_LOCAL6,
	"LOG_LOCAL7",	LOG_LOCAL7,
	/* severity */
	"LOG_EMERG",    LOG_EMERG,    
	"LOG_ALERT",	LOG_ALERT,   
	"LOG_CRIT",	LOG_CRIT,    
	"LOG_ERR",	LOG_ERR,     
	"LOG_WARNING",	LOG_WARNING, 
	"LOG_NOTICE",	LOG_NOTICE,  
	"LOG_INFO",	LOG_INFO,    
	"LOG_DEBUG",   	LOG_DEBUG,   
	/* options */
	"LOG_CONS",     LOG_CONS,   
	"LOG_NDELAY",	LOG_NDELAY, 
	"LOG_PID",    	LOG_PID,
	NULL
};

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
	scm_make_gsubr("rad-send-internal", 3, 0, 0, rad_send_internal);
	scm_make_gsubr("rad-get-server", 0, 0, 0, rad_get_server);

	scm_make_gsubr("rad-directory", 1, 0, 0, rad_directory);
	scm_make_gsubr("rad-dict-name->value", 2, 0, 0, rad_dict_name_to_value);
	scm_make_gsubr("rad-dict-value->name", 2, 0, 0, rad_dict_value_to_name);
	scm_make_gsubr("rad-dict-name->attr", 1, 0, 0, rad_dict_name_to_attr);
	scm_make_gsubr("rad-dict-pec->vendor", 1, 0, 0, rad_dict_pec_to_vendor);
	scm_make_gsubr("rad-read-no-echo", 1, 0, 0, rad_read_no_echo);

	scm_make_gsubr("rad-client-source-ip", 1, 0, 0, rad_client_source_ip);
	scm_make_gsubr("rad-client-timeout", 1, 0, 0, rad_client_timeout);
	scm_make_gsubr("rad-client-retry", 1, 0, 0, rad_client_retry);
	scm_make_gsubr("rad-client-set-server", 1, 0, 0, rad_client_set_server);
	scm_make_gsubr("rad-client-add-server", 1, 0, 0, rad_client_add_server);
	scm_make_gsubr("rad-client-list-servers", 0, 0, 0, rad_client_list_servers);
	scm_make_gsubr("rad-openlog", 3, 0, 0, rad_openlog);
	scm_make_gsubr("rad-syslog", 2, 0, 0, rad_syslog);
	scm_make_gsubr("rad-closelog", 1, 0, 0, rad_closelog);

	scm_loc = SCM_CDRLOC (scm_sysintern ("%raddb-path", SCM_EOL));
	*scm_loc = scm_makfrom0str(radius_dir);

	for (si = 0; syslog_kw[si].name; si++)
		scm_sysintern(syslog_kw[si].name,
			      SCM_MAKINUM(syslog_kw[si].tok));
	
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

SCM
scm_makenum(val)
	unsigned long val;
{
	if (SCM_FIXABLE((long)val)) {
		return SCM_MAKINUM(val);
	}
#ifdef SCM_BIGDIG
	return scm_long2big(val);
#else  /* SCM_BIGDIG */
	return scm_make_real((double) val);
#endif /* SCM_BIGDIG */ 
}

SCM
rad_directory(g_dir)
	SCM g_dir;
{
	SCM_ASSERT(SCM_NIMP(g_dir) && SCM_STRINGP(g_dir),
		   g_dir, SCM_ARG1, "rad-directory");
	radius_dir = SCM_CHARS(g_dir);
	if (dict_init())
		return SCM_BOOL_F;
	return SCM_BOOL_T;
}
	
/*
 * (define (rad-send-internal port code pairlist) ... )
 */
SCM
rad_send_internal(g_port, g_code, g_pairs)
	SCM g_port;
	SCM g_code;
	SCM g_pairs;
{
	int port;
	int code;
	VALUE_PAIR *pairlist;
	SCM g_auth, g_plist;
	AUTH_REQ *auth;
	
	SCM_ASSERT((SCM_IMP(g_port) && SCM_INUMP(g_port)),
		    g_port, SCM_ARG1, "rad-send-internal");
	port = SCM_INUM(g_port);
	SCM_ASSERT((SCM_IMP(g_code) && SCM_INUMP(g_code)),
		   g_code, SCM_ARG2, "rad-send-internal");
	code = SCM_INUM(g_code);
	SCM_ASSERT(((SCM_IMP(g_pairs) && SCM_EOL == g_pairs) ||
		    (SCM_NIMP(g_pairs) && SCM_CONSP(g_pairs))),
		   g_pairs, SCM_ARG3, "rad-send-internal");

	if (SCM_IMP(g_pairs) && SCM_EOL == g_pairs)
		pairlist = NULL;
	else
		pairlist = scheme_to_list(g_pairs);

	auth = radclient_send(radclient, port, code, pairlist);
	if (!auth)
		return SCM_EOL;
	/*
	 * Construct scheme return values
	 */
	g_auth = SCM_MAKINUM(auth->code);
	g_plist = list_to_scheme(auth->request);
	
	return scm_cons(g_auth, g_plist);
}

SCM
rad_client_list_servers()
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

SCM
rad_get_server()
{
	return scm_makfrom0str(radclient->first_server->name);
}

SERVER *
scheme_to_server(g_list, func)
	SCM g_list;
	char *func;
{
	SERVER serv;
	SCM scm;
	
	SCM_ASSERT((SCM_NIMP(g_list) && SCM_CONSP(g_list)),
		   g_list, SCM_ARG1, func);
	
	scm = SCM_CAR(g_list);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm),
		   scm, SCM_ARG1, func);
	serv.name = SCM_CHARS(scm);

	scm = SCM_CADR(g_list);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm),
		   scm, SCM_ARG1, func);
	serv.addr = get_ipaddr(SCM_CHARS(scm));
	if (serv.addr == 0) 
		scm_misc_error(func,
			       "Bad hostname or ip address ~S\n",
			       scm);

	scm = SCM_CADDR(g_list);
	SCM_ASSERT(SCM_NIMP(scm) && SCM_STRINGP(scm) &&
		   SCM_LENGTH(scm) <= AUTH_PASS_LEN,
		   scm, SCM_ARG1, func);
	strncpy(serv.secret, SCM_CHARS(scm), sizeof(serv.secret));

	scm = SCM_CADDDR(g_list);
	SCM_ASSERT(SCM_IMP(scm) && SCM_INUMP(scm),
		   scm, SCM_ARG1, func);
	serv.port[PORT_AUTH] = SCM_INUM(scm);
	
	scm = SCM_CAR(SCM_CDDDDR(g_list));
	SCM_ASSERT(SCM_IMP(scm) && SCM_INUMP(scm),
		   scm, SCM_ARG1, func);
	serv.port[PORT_ACCT] = SCM_INUM(scm);

	scm = SCM_CAR(SCM_CDR(SCM_CDDDDR(g_list)));
	SCM_ASSERT(SCM_IMP(scm) && SCM_INUMP(scm),
		   scm, SCM_ARG1, func);
	serv.port[PORT_CNTL] = SCM_INUM(scm);

	return radclient_alloc_server(&serv);
}

#define FUNC_NAME "rad-client-add-server"
SCM
rad_client_add_server(g_list)
	SCM g_list;
{
	radclient->first_server =
		radclient_append_server(radclient->first_server,
					scheme_to_server(g_list, FUNC_NAME));
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-client-set-server"
SCM
rad_client_set_server(g_list)
	SCM g_list;
{
	SERVER *s = scheme_to_server(g_list, FUNC_NAME);

	radclient_clear_server_list(radclient->first_server);
	radclient->first_server = radclient_append_server(NULL, s);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-client-source-ip"
SCM
rad_client_source_ip(g_ip)
	SCM g_ip;
{
	UINT4 ip;
	
	SCM_ASSERT((SCM_NIMP(g_ip) && SCM_STRINGP(g_ip)),
		   g_ip, SCM_ARG1, FUNC_NAME);
	ip = get_ipaddr(SCM_CHARS(g_ip));
	if (ip)
		radclient->source_ip = ip;
	else {
		scm_misc_error(FUNC_NAME,
			       "Invalid IP/hostname: ~S",
			       SCM_LIST1(g_ip));
		return SCM_BOOL_F;
	}

	return SCM_BOOL_T;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-client-timeout"
SCM
rad_client_timeout(g_to)
	SCM g_to;
{
	SCM_ASSERT(SCM_IMP(g_to) && SCM_INUMP(g_to),
		   g_to, SCM_ARG1, FUNC_NAME);
	radclient->timeout = SCM_INUM(g_to);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-client-retry"
SCM
rad_client_retry(g_retry)
	SCM g_retry;
{
	SCM_ASSERT(SCM_IMP(g_retry) && SCM_INUMP(g_retry),
		   g_retry, SCM_ARG1, FUNC_NAME);
	radclient->retries = SCM_INUM(g_retry);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM
rad_dict_name_to_attr(g_name)
	SCM g_name;
{
	DICT_ATTR *attr;
	int vendor;
	
	if (SCM_IMP(g_name) && SCM_INUMP(g_name)) {
		attr = attr_number_to_dict(SCM_INUM(g_name));
	} else if (SCM_NIMP(g_name) && SCM_STRINGP(g_name)) {
		attr = attr_name_to_dict(SCM_CHARS(g_name));
	} else {
		SCM_ASSERT(0,
			   g_name, SCM_ARG1, "rad-dict-name->atr");
	}

	if (!attr)
		return SCM_BOOL_F;

	vendor = VENDOR(attr->value);
	return SCM_LIST4(scm_makfrom0str(attr->name),
			 SCM_MAKINUM(vendor ?
				     attr->value - (vendor << 16) :
				     attr->value),
			 SCM_MAKINUM(attr->type),
			 vendor ?
			 SCM_MAKINUM(vendor_id_to_pec(vendor)) :
			 SCM_BOOL_F);
}

SCM
rad_dict_value_to_name(g_attr, g_value)
	SCM g_attr;
	SCM g_value;
{
	DICT_ATTR *attr;
	DICT_VALUE *val;

	if (SCM_IMP(g_attr) && SCM_INUMP(g_attr)) {
		attr = attr_number_to_dict(SCM_INUM(g_attr));
	} else if (SCM_NIMP(g_attr) && SCM_STRINGP(g_attr)) {
		attr = attr_name_to_dict(SCM_CHARS(g_attr));
	}

	if (!attr) {
		scm_misc_error("rad-dict-value->name",
			       "Unknown attribute: ~S",
			       SCM_LIST1(g_attr));
		return SCM_BOOL_F;
	}

	SCM_ASSERT((SCM_IMP(g_value) && SCM_INUMP(g_value)),
		   g_value, SCM_ARG1, "rad-dict-value->name");
	val = value_lookup(SCM_INUM(g_value), attr->name);
	return val ? scm_makfrom0str(val->name) : SCM_BOOL_F;
}

SCM
rad_dict_name_to_value(g_attr, g_value)
	SCM g_attr;
	SCM g_value;
{
	DICT_ATTR *attr;
	DICT_VALUE *val;
	
	if (SCM_IMP(g_attr) && SCM_INUMP(g_attr)) {
		attr = attr_number_to_dict(SCM_INUM(g_attr));
	} else if (SCM_NIMP(g_attr) && SCM_STRINGP(g_attr)) {
		attr = attr_name_to_dict(SCM_CHARS(g_attr));
	}
	if (!attr) {
		scm_misc_error("rad-dict-name->value",
			       "Unknown attribute: ~S",
			       SCM_LIST1(g_attr));
		return SCM_BOOL_F;
	}
	SCM_ASSERT((SCM_NIMP(g_value) && SCM_STRINGP(g_value)),
		   g_value, SCM_ARG1, "rad-dict-name->value");
	
	/*FIXME:
	  val = value_name_to_value_strict(attr->value, SCM_CHARS(g_value));
	  */
	val = value_name_to_value(SCM_CHARS(g_value));
	return val ? scm_makenum(val->value) : SCM_BOOL_F;
}

SCM
rad_dict_pec_to_vendor(g_pec)
	SCM g_pec;
{
	char *s;
	
	SCM_ASSERT(SCM_IMP(g_pec) && SCM_INUMP(g_pec),
		   g_pec, SCM_ARG1, "rad-dict-pec->vendor");
	s = vendor_pec_to_name(SCM_INUM(g_pec));
	return s ? scm_makfrom0str(s) : SCM_BOOL_F;
}

SCM
rad_read_no_echo(g_prompt)
	SCM g_prompt;
{
	char *s;
	
	SCM_ASSERT((SCM_NIMP(g_prompt) && SCM_STRINGP(g_prompt)),
		   g_prompt, SCM_ARG1, "rad-read-no-echo");
	s = getpass(SCM_CHARS(g_prompt));
	return scm_makfrom0str(s);
}


SCM
list_to_scheme(pair)
	VALUE_PAIR *pair;
{
	SCM scm_first, scm_last, scm_attr, scm_value, new;
	DICT_ATTR *dict;
	int goon = 0;
	
	for (; pair; pair = pair->next) {
		if (dict = attr_number_to_dict(pair->attribute)) 
			scm_attr = scm_makfrom0str(dict->name);
		else
			scm_attr = SCM_MAKINUM(pair->attribute);
		switch (pair->type) {
		case PW_TYPE_STRING:
		case PW_TYPE_DATE:
			scm_value = scm_makfrom0str(pair->strvalue);
			break;
		case PW_TYPE_INTEGER:
			scm_value = scm_makenum(pair->lvalue);
			break;
		case PW_TYPE_IPADDR:
			scm_value = scm_ulong2num(pair->lvalue);
			break;
		default:
			abort();
		}

		if (!goon) {
			goon++;
			SCM_NEWCELL(scm_first);
			scm_last = scm_first;
		} else {
			SCM_NEWCELL(new);
			SCM_SETCDR(scm_last, new);
			scm_last = new;
		}
		SCM_SETCAR(scm_last, scm_cons(scm_attr, scm_value));
	}
	if (goon)
		SCM_SETCDR(scm_last, SCM_EOL);
	else
		scm_first = SCM_EOL;
	return scm_first;
}

VALUE_PAIR *
scheme_to_list(list)
	SCM list;
{
	VALUE_PAIR *first, *last, *p, pair;
	SCM car;
	int cnt=0;

	first = last = NULL;
	do {
		car = SCM_CAR(list);
		scheme_to_pair(car, &pair);
		p = alloc_entry(sizeof(VALUE_PAIR));
		*p = pair;
		p->next = NULL;
		if (!last)
			first = p;
		else
			last->next = p;
		last = p;

		list = SCM_CDR(list);
		cnt++;
	} while (list != SCM_EOL);
	return first;
}

/*
 * (define scm (cons NAME VALUE))
 */

int
scheme_to_pair(scm, pair)
	SCM scm;
	VALUE_PAIR *pair;
{
	SCM car, cdr;
	DICT_ATTR *dict;
	DICT_VALUE *val;
	
	SCM_ASSERT(SCM_NIMP(scm) && SCM_CONSP(scm),
		   scm, SCM_ARGn, "%%scheme_to_pair");
	car = SCM_CAR(scm);
	cdr = SCM_CDR(scm);

	if (SCM_IMP(car) && SCM_INUMP(car)) {
		pair->attribute = SCM_INUM(car);
		dict = attr_number_to_dict(pair->attribute);
		if (!dict) {
			scm_misc_error("%%scheme_to_pair",
				       "Unknown attribute: ~S",
				       SCM_LIST1(car));
		}
		pair->name = dict->name;
	} else if (SCM_NIMP(car) && SCM_STRINGP(car)) {
		pair->name = SCM_CHARS(car);
		dict = attr_name_to_dict(pair->name);
		if (!dict) {
			scm_misc_error("%%scheme_to_pair",
				       "Unknown attribute: ~S",
				       SCM_LIST1(car));
		}
		pair->attribute = dict->value;
	} else
		scm_misc_error("%%scheme_to_pair",
			       "bad attribute: ~S",
			       SCM_LIST1(car));
	pair->type = dict->type;
	pair->operator = PW_OPERATOR_EQUAL;

	switch (pair->type) {
	case PW_TYPE_INTEGER:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair->lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair->lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			char *name = SCM_CHARS(cdr);
			val = value_name_to_value(name);
			if (val) {
				pair->lvalue = val->value;
			} else {
				pair->lvalue = strtol(name, &name, 0);
				if (*name)
					scm_misc_error("%%scheme_to_pair",
						       "Bad value: ~S",
						       SCM_LIST1(cdr));
			}
		} else
			SCM_OUTOFRANGE;
		break;
	case PW_TYPE_IPADDR:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair->lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair->lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			pair->lvalue = get_ipaddr(SCM_CHARS(cdr));
		} else
			SCM_OUTOFRANGE;
		break;
	case PW_TYPE_STRING:
	case PW_TYPE_DATE:
		SCM_ASSERT(SCM_NIMP(cdr) && SCM_STRINGP(cdr),
			   car, SCM_ARGn, "%%scheme_to_pair");
		pair->strvalue = make_string(SCM_CHARS(cdr));
		pair->strlength = strlen(pair->strvalue);
		break;
	default:
		abort();
	}

	return 0;
}

int
parse_facility(list)
	SCM list;
{
	SCM car;
	int accval = 0;
	int val;
	do {
		car = SCM_CAR(list);
		val = 0;
		
		if (SCM_IMP(car) && SCM_INUMP(car)) 
			val = SCM_INUM(car);
		else if (SCM_NIMP(car) && SCM_STRINGP(car))
			val = xlat_keyword(syslog_kw, SCM_CHARS(car), 0);
		else
			continue;
		accval |= val;
	} while ((list = SCM_CDR(list)) != SCM_EOL);
	return accval;
}

#define FUNC_NAME "rad-openlog"
SCM
rad_openlog(g_ident, g_option, g_facility)
	SCM g_ident;
	SCM g_option;
	SCM g_facility;
{
	char *ident;
	int option, facility;

	if (g_ident == SCM_BOOL_F)
		ident = "radscm";
	else {
		SCM_ASSERT(SCM_NIMP(g_ident) && SCM_STRINGP(g_ident),
			   g_ident, SCM_ARG1, FUNC_NAME);
		ident = SCM_CHARS(g_ident);
	}
	
	if (SCM_IMP(g_option) && SCM_INUMP(g_option)) {
		option = SCM_INUM(g_option);
	} else if (SCM_BIGP(g_option)) {
		option = (UINT4) scm_big2dbl(g_option);
	} else {
		option = parse_facility(g_option);
	}

	if (SCM_IMP(g_facility) && SCM_INUMP(g_facility)) {
		facility = SCM_INUM(g_facility);
	} else if (SCM_BIGP(g_facility)) {
		facility = (UINT4) scm_big2dbl(g_facility);
	} else {
		facility = parse_facility(g_facility);
	}

	openlog(ident, option, facility);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-syslog"
SCM
rad_syslog(g_prio, g_text)
	SCM g_prio;
	SCM g_text;
{
	int prio;

	if (g_prio == SCM_BOOL_F) {
		prio = LOG_INFO;
	} else if (SCM_IMP(g_prio) && SCM_INUMP(g_prio)) {
		prio = SCM_INUM(g_prio);
	} else if (SCM_BIGP(g_prio)) {
		prio = (UINT4) scm_big2dbl(g_prio);
	} else {
		prio = parse_facility(g_prio);
	}

	SCM_ASSERT(SCM_NIMP(g_text) && SCM_STRINGP(g_text),
		   g_text, SCM_ARG1, FUNC_NAME);
	syslog(prio, "%s", SCM_CHARS(g_text));
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define FUNC_NAME "rad-closelog"
SCM
rad_closelog()
{
	closelog();
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
