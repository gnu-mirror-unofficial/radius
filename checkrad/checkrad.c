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
/* Checks if the user has already logged in to the given NAS
 * usage: checkrad nas_type nas_ip nas_port login session_id
 * Return value:
 *        0    the user is not logged in
 *        1    the user is logged in
 *        <0   error (== I don't know)
 */
#define RADIUS_MODULE 2

#ifndef lint
static char rcsid[] = "$Id$";
#endif

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sysdep.h>
#include <radiusd.h>
#include <mem.h>
#include <obstack1.h>
#include <log.h>
#include <checkrad.h>

#include <snmp.h>
#include <snmp_impl.h>
#include <asn1.h>
#include <snmp_api.h>
#include <snmp_vars.h>

char *nas_type = NULL;
char *nas_port = NULL;
char *username = NULL;
char *session_id = NULL;
char *snmp_oid = NULL;
char *snmp_match = NULL;
char *password = NULL;
struct obstack stk;

static void install(char *s);

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	char *p;
	char *host = NULL;
	Check checkfun = NULL;
	int port = 0;
	
	obstack_init(&stk);
	initlog(argv[0]);
	
	while ((c = getopt(argc, argv, "d:h:p:t:u:s:x:")) != EOF) {
		switch (c) {
		case 'd':
			radius_dir = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			nas_port = optarg;
			if (nas_port[0] == 's' || nas_port[0] == 'S')
				nas_port++;
			break;
		case 't':
			nas_type = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 's':
			session_id = optarg;
			break;
		case 'x':
			set_debug_levels(optarg);
			break;
		default:
			radlog(L_ERR, _("bad argument"));
		}
	}

	/*
	 * Parse extra args
	 */
	for ( ; optind < argc; optind++) {
		for (p = strtok(argv[optind], ","); p; p = strtok(NULL, ",")) 
			install(p);
	}
	
	radpath_init();
	
	if (!nas_type || !host || !nas_port || !username || !session_id) {
		printf(_("usage: checkrad [-h host][-p nas_port][-t type][-u user][-s session_id]\n"));
		return -1;
	}

	checkfun = read_config();
	password = read_clients(host);
	
	debug(1, ("started: host %s, type %s, user %s, port %s, sid %s",
		   host, nas_type, username, nas_port, session_id));

	if (checkfun)
		return checkfun(host);

	radlog(L_ERR, _("unknown NAS type: %s"), nas_type);
	return -1; /* unknown type */
}

/* Replace: %u  -- username
 *          %s  -- session id
 *          %p  -- port no
 *          %P  -- port no + 1
 */
char *
checkrad_xlat(str)
	char *str;
{
	char *ptr;
	int len;
	char buf[24];
	
	while (*str) {
		if (*str == '%') {
			switch (str[1]) {
			case 'u':
				ptr = username;
				break;
			case 's':
				ptr = session_id;
				break;
			case 'd':
				sprintf(buf, "%d", strtol(session_id, NULL, 16));
				ptr = buf;
				break;
			case 'p':
				ptr = nas_port;
				break;
			case 'P':
				sprintf(buf, "%d", atoi(nas_port) + 1);
				ptr = buf;
				break;
			default:
				ptr = NULL;
				obstack_grow(&stk, str, 2);
			}
			if (ptr) {
				len = strlen(ptr);
				obstack_grow(&stk, ptr, len);
			}
			str += 2;
		} else {
			obstack_1grow(&stk, *str);
			str++;
		}
	}
	obstack_1grow(&stk, 0);
	return obstack_finish(&stk);
}

/*ARGSUSED*/
int
callback(type, sp, requid, pdu, closure)
	int type;
	struct snmp_session *sp;
	int requid;
	struct snmp_pdu *pdu;
	void *closure;
{
	int rc = 0;
	struct variable_list *vlist;
	UINT4 ip;
	
	if (type != RECEIVED_MESSAGE)
		return 1;

	for (vlist = pdu->variables; rc == 0 && vlist;
				     vlist = vlist->next_variable)  
		switch (vlist->type) {
		case SMI_STRING:
			rc = strncmp(snmp_match, vlist->val.string,
				     strlen(snmp_match)) == 0;
			debug(2, ("(STRING) %s: %d", vlist->val.string, rc));
			break;
		case SMI_INTEGER:
		case SMI_COUNTER32:
		case SMI_COUNTER64:
			rc = atoi(snmp_match) == *vlist->val.integer;
			debug(2, ("(INT) %d: %d", *vlist->val.integer, rc));
			break;
		case SMI_IPADDRESS:
			ip = htonl(get_ipaddr(snmp_match));
			rc = memcmp(&ip, vlist->val.string, sizeof(ip)) == 0;
			debug(2, ("(IPADDR) %d: %d",
				  *(UINT4*)vlist->val.string, rc));
			break;
		}

	*(int*)closure = rc;
	
	return 1;
}

/*ARGSUSED*/
int
snmp_check(nas_ip)
	char *nas_ip;
{
	int rc = -1;
	struct snmp_pdu *pdu;
        struct snmp_session *sp, session;
	struct variable_list *vlist;
	int namelen;
	oid *name;
	int numfds;
	fd_set fdset;
	struct timeval timeout;
	int block = 0;
	oid * create_oid(char *str, int *length);
	
	if (!password) {
		radlog(L_ERR, _("no snmp_community"));
		return -1;
	}
	if (!snmp_oid) {
		radlog(L_ERR, _("no snmp_oid"));
		return -1;
	}
	if (!snmp_match) {
		radlog(L_ERR, _("no snmp_match"));
		return -1;
	}

	debug(5, ("matching %s", snmp_match));

	bzero(&session, sizeof(session));
	session.Version = SNMP_VERSION_1;
	session.community = password;
	session.community_len = strlen(session.community);
	session.retries = ilookup("retries", 3);
	session.timeout = ilookup("timeout", 2);
	session.peername = nas_ip;
	session.remote_port = ilookup("port", 161);
	session.local_port = 0;
	session.callback = callback;
	session.callback_magic = &rc;
	
	sp = snmp_open(&session);

	pdu = snmp_pdu_create(SNMP_PDU_GET);

	name = create_oid(snmp_oid, &namelen);
	vlist = snmp_var_new(name, namelen);
	pdu->variables = vlist;

	snmp_send(sp, pdu);

	timeout.tv_usec = 0;
	timeout.tv_sec = 1; /* FIXME: should be configurable? */
	if (snmp_select_info(&numfds, &fdset, &timeout, &block)) {
		snmp_read(&fdset);
	}

	debug(5, ("result: %d", rc));
	snmp_close(sp);
	return rc;
}

oid *
create_oid(str, length)
	char *str;
	int *length;
{
	char *tok;
	int len;
	oid *name, *p;

	if (*str == '.')
		str++;
	
	for (tok = str, len = 0; *tok; tok++)
		if (*tok == '.')
			len++;
	name = emalloc(sizeof(*name) * (len+1));

	p = name;
	tok = str;
	for (;;) {
		*p++ = strtol(tok, &tok, 10);
		if (*tok == 0)
			break;
		if (*tok++ != '.') {
			radlog(L_ERR, "malformed oid near %s", tok-1);
			break;
		}
	} 

	*length = p-name;
	return name;
}

/* additional args */
struct xarg {
	struct xarg *next;
	char *name;
	char *value;
};

struct xarg *xargs;

struct xarg *
lookup(name)
	char *name;
{
	struct xarg *p;

	for (p = xargs; p; p = p->next)
		if (strcmp(p->name, name) == 0)
			break;
	return p;
}

int
ilookup(name, defval)
	char *name;
	int defval;
{
	struct xarg *p = lookup(name);
	return p ? atoi(p->value) : defval;
}

char *
slookup(name, defval)
	char *name;
	char *defval;
{
	struct xarg *p = lookup(name);
	return p ? p->value : defval;
}

void
install(s)
	char *s;
{
	struct xarg *p;

	p = emalloc(sizeof(*p));
	s = estrdup(s);
	p->name = s;
	if (s = strchr(s, '=')) {
		*s++ = 0;
		p->value = s;
	} else
		p->value = NULL;
	p->next = xargs;
	xargs = p;
}





