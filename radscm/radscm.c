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

#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <libguile.h>
#include <radiusd.h>
#include <radutmp.h>
#include <radclient.h>

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

SCM_DEFINE(rad_directory, "rad-directory", 1, 0, 0,
	   (SCM g_dir),
	   "Sets radius database directory to dir")
#define FUNC_NAME s_rad_directory
{
	SCM_ASSERT(SCM_NIMP(g_dir) && SCM_STRINGP(g_dir),
		   g_dir, SCM_ARG1, "rad-directory");
	radius_dir = SCM_CHARS(g_dir);
	if (dict_init())
		return SCM_BOOL_F;
	return SCM_BOOL_T;
}
#undef FUNC_NAME

/*
 * (define (rad-send-internal port code pairlist) ... )
 */
SCM_DEFINE(rad_send_internal, "rad-send-internal", 3, 0, 0,
	   (SCM g_port, SCM g_code, SCM g_pairs),
"(rad-send-internal PORT-NUMBER CODE-NUMBER PAIR-LIST)\n"
"Sends the request to currently selected server.\n"
"PORT-NUMBER	Port to use.\n"
"			0 - Authentication port\n"
"			1 - Accounting port\n"
"			2 - Control port\n"
"		The actual port numbers are those configured for\n"
"		the given server.\n"
"CODE-NUMBER	Request code.\n"
"PAIR-LIST	List of Attribute-value pairs. Each pair is:\n"
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

SCM_DEFINE(rad_client_add_server, "rad-client-add-server", 1, 0, 0,
	   (SCM g_list),
	   "Add a server to the list of configured radius servers")
#define FUNC_NAME s_rad_client_add_server
{
	radclient->first_server =
		radclient_append_server(radclient->first_server,
					scheme_to_server(g_list, FUNC_NAME));
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_set_server, "rad-client-set-server", 1, 0, 0, 
	   (SCM g_list),
(rad-client-set-server LIST)
"Selects for use the server described by LIST. A LIST should be:\n"
"\n"
"	(list ID-STRING HOST-STRING SECRET-STRING AUTH-NUM ACCT-NUM CNTL-NUM)\n"
"Where:\n"
"	ID-STRING	Server ID\n"
"	HOST-STRING	Server hostname or IP address\n"
"	SECRET-STRING	Shared secret key to use\n"
"	AUTH-NUM	Authentication port number\n"
"	ACCT-NUM	Accounting port number\n"
"	CNTL-NUM	Control channel port number\n")
#define FUNC_NAME s_rad_client_set_server
{
	SERVER *s = scheme_to_server(g_list, FUNC_NAME);

	radclient_clear_server_list(radclient->first_server);
	radclient->first_server = radclient_append_server(NULL, s);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_source_ip, "rad-client-source-ip", 1, 0, 0,
	   (SCM g_ip),
"Set source IP address for packets coming from this client\n")
#define FUNC_NAME s_rad_client_source_ip
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

SCM_DEFINE(rad_client_timeout, "rad-client-timeout", 1, 0, 0,
	   (SCM g_to),
"Sets the timeout for waiting for the server reply.\n")
#define FUNC_NAME s_rad_client_timeout
{
	SCM_ASSERT(SCM_IMP(g_to) && SCM_INUMP(g_to),
		   g_to, SCM_ARG1, FUNC_NAME);
	radclient->timeout = SCM_INUM(g_to);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_client_retry, "rad-client-retry", 1, 0, 0,
	   (SCM g_retry),
"Sets the number of retries for sending requests to a radius server.")
#define FUNC_NAME s_rad_client_retry
{
	SCM_ASSERT(SCM_IMP(g_retry) && SCM_INUMP(g_retry),
		   g_retry, SCM_ARG1, FUNC_NAME);
	radclient->retries = SCM_INUM(g_retry);
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM_DEFINE(rad_dict_name_to_attr, "rad-dict-name->attr", 1, 0, 0,
	   (SCM g_name),
"Returns a dictionary entry for the given attribute name or #f if\n"
"no such name was found in the dictionary.\n"
"The entry is a list of the form:\n"
"\n"
"	(NAME-STRING ATTR-NUMBER TYPE-NUMBER VENDOR)\n"
"\n"
"Where,\n"
"	NAME-STRING	is the attribute name,\n"
"	VALUE-NUMBER	is the attribute number,\n"
"	TYPE-NUMBER	is the attribute type\n"
"	VENDOR		is the vendor PEC, if the attribute is a\n"
"			Vendor-Specific one, or #f otherwise.\n")
#define FUNC_NAME s_rad_dict_name_to_attr	   
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
#undef FUNC_NAME

SCM_DEFINE(rad_dict_value_to_name, "rad-dict-value->name", 2, 0, 0,
	   (SCM g_attr, SCM g_value),
"Returns a dictionary name of the given value of an integer-type\n"
"attribute\n") 	   
#define FUNC_NAME s_rad_dict_value_to_name
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
#undef FUNC_NAME

SCM_DEFINE(rad_dict_name_to_value, "rad-dict-name->value", 2, 0, 0,
	   (SCM g_attr, SCM g_value),
"Convert a symbolic attribute value name into its integer representation\n")
#define FUNC_NAME s_rad_dict_name_to_value	
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
#undef FUNC_NAME

SCM_DEFINE(rad_dict_pec_to_vendor, "rad-dict-pec->vendor", 1, 0, 0,
	   (SCM g_pec),
"Converts PEC to the vendor name")	   
#define FUNC_NAME s_rad_dict_pec_to_vendor
{
	char *s;
	
	SCM_ASSERT(SCM_IMP(g_pec) && SCM_INUMP(g_pec),
		   g_pec, SCM_ARG1, "rad-dict-pec->vendor");
	s = vendor_pec_to_name(SCM_INUM(g_pec));
	return s ? scm_makfrom0str(s) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE(rad_read_no_echo, "rad-read-no-echo", 1, 0, 0,
	   (SCM g_prompt),
"Prints the given PROMPT-STRING, disables echoing, reads a string up to the\n"
"next newline character, restores echoing and returns the string entered.\n"
"This is the interface to the C getpass(3) function.\n")
#define FUNC_NAME s_rad_read_no_echo	   
{
	char *s;
	
	SCM_ASSERT((SCM_NIMP(g_prompt) && SCM_STRINGP(g_prompt)),
		   g_prompt, SCM_ARG1, "rad-read-no-echo");
	s = getpass(SCM_CHARS(g_prompt));
	return scm_makfrom0str(s);
}
#undef FUNC_NAME

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

SCM_DEFINE(rad_openlog, "rad-openlog", 3, 0, 0,
	   (SCM g_ident, SCM g_option, SCM g_facility),
"FIXME: rad-openlog docstring")	   
#define FUNC_NAME s_rad_openlog
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

SCM_DEFINE(rad_syslog, "rad-syslog", 2, 0, 0,
	   (SCM g_prio, SCM g_text),
"FIXME: rad-syslog docstring")	   
#define FUNC_NAME s_rad_syslog
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

SCM_DEFINE(rad_closelog, "rad-closelog", 0, 0, 0,
	   (),
"FIXME: rad-closelog docstring")	   
#define FUNC_NAME s_rad_closelog
{
	closelog();
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

#define RADUTMP_FIELD_LOGIN       0
#define RADUTMP_FIELD_ORIG_LOGIN  1
#define RADUTMP_FIELD_PORT        2
#define RADUTMP_FIELD_PORT_TYPE   3
#define RADUTMP_FIELD_SESSION_ID  4
#define RADUTMP_FIELD_CALLER_ID   5
#define RADUTMP_FIELD_FRAMED_IP   6
#define RADUTMP_FIELD_NAS_IP      7
#define RADUTMP_FIELD_PROTO       8
#define RADUTMP_NUM_FIELDS        9

SCM_DEFINE(rad_utmp_putent, "rad-utmp-putent", 4, 1, 0,
	   (SCM STATUS,
	    SCM DELAY,
	    SCM LIST,
	    SCM RADUTMP_FILE,
	    SCM RADWTMP_FILE),
"Write the supplied data into the radutmp file. If RADWTMP_FILE is not nil
the constructed entry is also appended to WTMP_FILE.")
#define FUNC_NAME s_rad_utmp_putent
{
	int status;
	struct radutmp ut;
	char *file_name;
	SCM elt;
	int num;
	
	/* status */
	SCM_ASSERT(SCM_IMP(STATUS) && SCM_INUMP(STATUS),
		   STATUS, SCM_ARG1, FUNC_NAME);
	status = SCM_INUM(STATUS);

        /* initialize the radutmp structure */
	memset(&ut, 0, sizeof(ut));

	/* Now fill it */
	
	/* Time */
	time(&ut.time);

        /* Delay */
	if (SCM_IMP(DELAY) && SCM_INUMP(DELAY)) 
		ut.delay = SCM_INUM(DELAY);
	else if (SCM_BIGP(DELAY)) 
		ut.delay = (UINT4) scm_big2dbl(DELAY);
	else
		SCM_ASSERT(0,
			   DELAY, SCM_ARG2, FUNC_NAME);

	/* Rest of fields */
	SCM_ASSERT((SCM_NIMP(LIST) && SCM_CONSP(LIST)),
		   LIST, SCM_ARG3, FUNC_NAME);

	num = 0;
	while (num < RADUTMP_NUM_FIELDS &&
		!(SCM_NIMP(LIST) && LIST == SCM_EOL)) {

		elt = SCM_CAR(LIST);
		LIST = SCM_CDR(LIST);

		switch (num++) {
		case RADUTMP_FIELD_LOGIN:
			/* login name */
			if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
				scm_misc_error(FUNC_NAME,
					       "~S: login name should be string",
					       SCM_LIST1(elt));
			}
			strncpy(ut.login, SCM_CHARS(elt), sizeof(ut.login));
			ut.login[sizeof(ut.login)-1] = 0;
			break;
			
		case RADUTMP_FIELD_ORIG_LOGIN:
			/* original login name */
			if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
				scm_misc_error(FUNC_NAME,
					       "~S: orig login name should be string",
					       SCM_LIST1(elt));
			}
			strncpy(ut.orig_login, SCM_CHARS(elt),
				sizeof(ut.orig_login));
			ut.orig_login[sizeof(ut.orig_login)-1] = 0;
			break;

		case RADUTMP_FIELD_PORT:
			/* port number */
			if (!(SCM_IMP(elt) && SCM_INUMP(elt))) {
				scm_misc_error(FUNC_NAME,
					       "~S: port number should be integer",
					       SCM_LIST1(elt));
			}
			ut.nas_port = SCM_INUM(elt);
			break;
			
		case RADUTMP_FIELD_SESSION_ID:
			/* session id */
			if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
				scm_misc_error(FUNC_NAME,
					       "~S: session ID should be string",
					       SCM_LIST1(elt));
			}
			strncpy(ut.session_id, SCM_CHARS(elt),
				sizeof(ut.session_id));
			ut.session_id[sizeof(ut.session_id)-1] = 0;
			
		case RADUTMP_FIELD_NAS_IP:
			/* NAS IP address */
			if (SCM_IMP(elt) && SCM_INUMP(elt)) 
				ut.nas_address = SCM_INUM(elt);
			else if (SCM_BIGP(elt)) 
				ut.nas_address = (UINT4) scm_big2dbl(elt);
			else if (SCM_NIMP(elt) && SCM_STRINGP(elt)) 
				ut.nas_address = get_ipaddr(SCM_CHARS(elt));
			else if (SCM_NIMP(elt) && SCM_STRINGP(elt))
				ut.nas_address = ipstr2long(SCM_CHARS(elt));
			else 
				scm_misc_error(FUNC_NAME,
					       "~S: NAS IP should be IP address",
					       SCM_LIST1(elt));
			ut.nas_address = htonl(ut.nas_address);
			break;
			
		case RADUTMP_FIELD_FRAMED_IP:
			/* Framed IP address */
			if (SCM_IMP(elt) && SCM_INUMP(elt)) 
				ut.framed_address = SCM_INUM(elt);
			else if (SCM_BIGP(elt)) 
				ut.framed_address = (UINT4) scm_big2dbl(elt);
			else if (SCM_NIMP(elt) && SCM_STRINGP(elt)) 
				ut.framed_address = get_ipaddr(SCM_CHARS(elt));
			else if (SCM_NIMP(elt) && SCM_STRINGP(elt))
				ut.framed_address = ipstr2long(SCM_CHARS(elt));
			else 
				scm_misc_error(FUNC_NAME,
					       "~S: Framed IP should be IP address",
					       SCM_LIST1(elt));
			ut.framed_address = htonl(ut.framed_address);
			break;
			
		case RADUTMP_FIELD_PROTO:
			/* Prototype */
			if (SCM_IMP(elt) && SCM_INUMP(elt)) 
				ut.proto = SCM_INUM(elt);
			else if (SCM_IMP(elt) && SCM_CHARP(elt))
				ut.proto = SCM_CHAR(elt);
			else
				scm_misc_error(FUNC_NAME,
					       "~S: Proto should be integer or character",
					       SCM_LIST1(elt));
			break;
			
			
		case RADUTMP_FIELD_PORT_TYPE:
			/* Port type */
			if (SCM_IMP(elt) && SCM_INUMP(elt)) 
				ut.porttype = SCM_INUM(elt);
			else if (SCM_IMP(elt) && SCM_CHARP(elt))
				ut.porttype = SCM_CHAR(elt);
			else
				scm_misc_error(FUNC_NAME,
					       "~S: Port type should be char or integer",
					       SCM_LIST1(elt));
			break;

		case RADUTMP_FIELD_CALLER_ID:
			/* Calling station ID */
			if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
				scm_misc_error(FUNC_NAME,
					       "~S: CLID should be string",
					       SCM_LIST1(elt));
			}
			strncpy(ut.caller_id, SCM_CHARS(elt),
				sizeof(ut.caller_id));
			ut.caller_id[sizeof(ut.caller_id)-1] = 0;
			break;
		}
	}


	/* FIXME: IF (LIST == SCM_EOL) ? */

        /* Finally, put it into radutmp file */

	/* Obtain the file name */
	SCM_ASSERT(SCM_NIMP(RADUTMP_FILE) && SCM_STRINGP(RADUTMP_FILE),
		   RADUTMP_FILE, SCM_ARG4, FUNC_NAME);

	file_name = SCM_CHARS(RADUTMP_FILE);
	radutmp_putent(file_name, &ut, status);

	/* Add to wtmp if necessary */
	if (!SCM_UNBNDP(RADWTMP_FILE)) {
		SCM_ASSERT(SCM_NIMP(RADWTMP_FILE) && SCM_STRINGP(RADWTMP_FILE),
			   RADWTMP_FILE, SCM_ARG5, FUNC_NAME); 
		file_name = SCM_CHARS(RADWTMP_FILE);
		radwtmp_putent(file_name, &ut);
	}

	return SCM_LIST3(scm_makenum(ut.duration),
			 scm_makenum(0),
			 scm_makenum(0));
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
	#include <radscm.x>

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
