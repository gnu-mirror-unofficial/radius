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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#define RADIUS_MODULE 18

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#define _XPG4_2
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <setjmp.h>
#include <errno.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#include <signal.h>

#include <obstack1.h>
#include <radiusd.h>
#include <radutmp.h>
#include <checkrad.h>

#include <snmp.h>
#include <snmp_impl.h>
#include <asn1.h>
#include <snmp_api.h>
#include <snmp_vars.h>

struct check_instance {
	char      *name;
	int       port;
	char      *sid;
	int       result;
	int       timeout;
	int       method;
	char      *func;
	RADCK_ARG *args;
	char      *hostname;
};

RADCK_ARG *lookup(RADCK_ARG *arg, char *name);
RADCK_ARG *dup_arg(RADCK_ARG *arg);
RADCK_ARG *merge_args(RADCK_ARG *prim, RADCK_ARG *sec);
struct check_instance * create_instance(struct check_instance *cptr,
					NAS *nas, struct radutmp *up);
void free_instance(struct check_instance *cptr);
char * slookup(struct check_instance *checkp, char *name, char *defval);
int ilookup(struct check_instance *checkp, char *name, int defval);
int compare(struct check_instance *checkp, char *str);


RADCK_ARG *
lookup(arg, name)
	RADCK_ARG *arg;
	char    *name;
{
	for (; arg && strcmp(arg->name, name); arg = arg->next)
		;
	return arg;
}

RADCK_ARG *
dup_arg(arg)
	RADCK_ARG *arg;
{
	RADCK_ARG *dp;

	dp = alloc_entry(sizeof(*arg));
	dp->name  = arg->name;
	dp->value = arg->value;
	return dp;
}

RADCK_ARG *
merge_args(prim, sec)
	RADCK_ARG *prim;
	RADCK_ARG *sec;
{
	RADCK_ARG *list, *p;

	list = NULL;
	for (; sec; sec = sec->next)
		if (!lookup(prim, sec->name)) {
			p = dup_arg(sec);
			p->next = list;
			list = p;
		}
	for (; prim; prim = prim->next) {
		p = dup_arg(prim);
		p->next = list;
		list = p;
	}
	return list;
}

struct check_instance *
create_instance(cptr, nas, up)
	struct check_instance *cptr;
	NAS *nas;
	struct radutmp *up;
{
	RADCK_TYPE *radck_type;
		
	cptr->name = up->orig_login;
	cptr->port = up->nas_port;
	cptr->sid  = up->session_id;
	cptr->result = -1;
	cptr->timeout = 0;
	cptr->hostname = nas->shortname ? nas->shortname : nas->longname;
	
	radck_type = find_radck_type(nas->nastype);
	cptr->method = radck_type->method;
	cptr->args = merge_args((RADCK_ARG*) nas->args, radck_type->args);
	cptr->func = slookup(cptr, "function", NULL);
	return cptr;
}

void
free_instance(cptr)
	struct check_instance *cptr;
{
	free_slist((struct slist*)cptr->args, NULL);
}

char *
slookup(checkp, name, defval)
	struct check_instance *checkp;
	char *name;
	char *defval;
{
	RADCK_ARG *arg;

	if (arg = lookup(checkp->args, name))
		return arg->value;
	return defval;
}

int
ilookup(checkp, name, defval)
	struct check_instance *checkp;
	char *name;
	int defval;
{
	RADCK_ARG *arg;

	if (arg = lookup(checkp->args, name))
		return atoi(arg->value);
	return defval;
}
	
int
compare(checkp, str)
	struct check_instance *checkp;
	char *str;
{
	return va_run_init(checkp->func, NULL,
			   "ssis",
			   str,
			   checkp->name,
			   checkp->port,
			   checkp->sid);
}


/* Replace: %u  -- username
 *          %s  -- session id
 *          %p  -- port no
 *          %P  -- port no + 1
 */
char *
checkrad_xlat(checkp, str)
	struct check_instance *checkp;
	char *str;
{
	char *ptr;
	int len;
	char buf[24];
	struct obstack stk;

	obstack_init(&stk);
	while (*str) {
		if (*str == '%') {
			switch (str[1]) {
			case 'u':
				ptr = checkp->name;
				break;
			case 's':
				ptr = checkp->sid;
				break;
			case 'd':
				sprintf(buf, "%d",
					strtol(checkp->sid, NULL, 16));
				ptr = buf;
				break;
			case 'p':
				sprintf(buf, "%d", checkp->port);
				ptr = buf;
				break;
			case 'P':
				sprintf(buf, "%d", checkp->port + 1);
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
	str = estrdup(obstack_finish(&stk));
	obstack_free(&stk, NULL);
	return str;
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
	struct check_instance *checkp = (struct check_instance *)closure;
	char buf[64];

	if (type == TIMED_OUT) {
		radlog(L_NOTICE,
		       _("timed out in waiting SNMP response from NAS %s"),
		       checkp->hostname);
		checkp->timeout++;
		return 1;
	}
	if (type != RECEIVED_MESSAGE)
		return 1;

	for (vlist = pdu->variables; rc == 0 && vlist;
				     vlist = vlist->next_variable)  
		switch (vlist->type) {
		case SMI_STRING:
			rc = compare(checkp, vlist->val.string);
			debug(2, ("(STRING) %s: %d", vlist->val.string, rc));
			break;
		case SMI_INTEGER:
		case SMI_COUNTER32:
		case SMI_COUNTER64:
			sprintf(buf, "%d", *vlist->val.integer);
			rc = compare(checkp, buf);
			debug(2, ("(INT) %d: %d", *vlist->val.integer, rc));
			break;
		case SMI_IPADDRESS:
			ipaddr2str(buf, *(UINT4*)vlist->val.string);
			rc = compare(checkp, buf);
			debug(2, ("(IPADDR) %d: %d",
				  *(UINT4*)vlist->val.string, rc));
			break;
		}

	checkp->result = rc;
	
	return 1;
}

int
snmp_check(checkp, nas)
	struct check_instance *checkp;
	NAS *nas;
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
	char *snmp_oid;
	oid * create_oid(char *str, int *length);
	
	if ((snmp_oid = slookup(checkp, "oid", NULL)) == NULL) {
		radlog(L_ERR, _("no snmp_oid"));
		return -1;
	}
	snmp_oid = checkrad_xlat(checkp, snmp_oid);
	
	bzero(&session, sizeof(session));
	session.Version = SNMP_VERSION_1;
	if ((session.community = slookup(checkp, "password", NULL)) == NULL &&
	    (session.community = slookup(checkp, "community", NULL)) == NULL)
		session.community = "public";
	session.community_len = strlen(session.community);
	session.retries = ilookup(checkp, "retries", 3);
	session.timeout = ilookup(checkp, "timeout", 2);
	session.peername = nas->longname;
	session.remote_port = ilookup(checkp, "port", 161);
	session.local_port = 0;
	session.callback = callback;
	session.callback_magic = checkp;
	
	sp = snmp_open(&session);

	pdu = snmp_pdu_create(SNMP_PDU_GET);

	name = create_oid(snmp_oid, &namelen);
	vlist = snmp_var_new(name, namelen);
	pdu->variables = vlist;

	debug(1, ("snmpget: %s:%d %s %s",
		  session.peername,
		  session.remote_port,
		  session.community,
		  snmp_oid));
	
	snmp_send(sp, pdu);

	numfds = 0;
	if (snmp_select_info(&numfds, &fdset, &timeout, &block)) {
		while (!checkp->timeout) {
			timeout.tv_usec = 0;
			timeout.tv_sec = 1; 
			rc = select(numfds, &fdset, NULL, NULL, &timeout);
			if (rc < 0) {
				if (errno == EINTR)
					continue;
				break;
			} else if (rc == 0) {
				snmp_timeout();
			} else {
				snmp_read(&fdset);
				break;
			}
		}
	}

	rc = checkp->result;
	snmp_close(sp);
	efree(snmp_oid);
	
	debug(1, ("result: %d", rc));
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

/*
 * Timeout handler 
 */
static jmp_buf to_env;

static RETSIGTYPE
alrm_handler()
{
	longjmp(to_env, 1);
}

#define MIN(a,b) ((a)<(b))?(a):(b)

int
finger_check(checkp, nas)
	struct check_instance *checkp;
	NAS *nas;
{
	char namebuf[RUT_NAMESIZE+1];
	int namelen;
	register FILE *fp;
	register int c, lastc;
	struct hostent *hp;
	struct sockaddr_in sin;
	int i, port;
	int s;
	struct iovec iov[3];
	struct msghdr msg;
	int found = 0;
	struct obstack stk;
	char *ptr;
	RETSIGTYPE (*handler)();
	unsigned int to;
	
	/* Copy at most RUT_NAMESIZE bytes from the user name */
	ptr = checkp->name;
	for (i = 0; i < RUT_NAMESIZE && *ptr; ++ptr, ++i)
		namebuf[i] = *ptr;
	namebuf[i] = 0;
	namelen = i;

	if (!(hp = gethostbyname(nas->longname))) {
		radlog(L_ERR, _("unknown host: %s"), nas->longname);
		return -1;
	}

	if ((port = ilookup(checkp, "port", 0)) == 0) {
		struct servent *sp;
		
		if (sp = getservbyname("finger", "tcp")) 
			port = sp->s_port;
		else
			port = htons(79);
	} else
		port = htons(port);
	
	sin.sin_family = hp->h_addrtype;
	memcpy(&sin.sin_addr, hp->h_addr,
	       MIN(hp->h_length,sizeof(sin.sin_addr)));
	sin.sin_port = port;
	if ((s = socket(hp->h_addrtype, SOCK_STREAM, 0)) < 0) {
		radlog(L_ERR|L_PERROR, "socket");
		return -1;
	}

	debug(1, ("finger %s@%s:%d",
		  namebuf, hp->h_name, ntohs(port)));

	/* have network connection; identify the host connected with */
	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof sin;
	msg.msg_iov = iov;
	msg.msg_iovlen = 0;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	
	/* send the name followed by <CR><LF> */
	iov[msg.msg_iovlen].iov_base = namebuf;
	iov[msg.msg_iovlen++].iov_len = namelen;
	iov[msg.msg_iovlen].iov_base = "\r\n";
	iov[msg.msg_iovlen++].iov_len = 2;

	/* "tcp=0" can be used to disable T/TCP compatibility to finger
	 * broken hosts
	 */
	if (ilookup(checkp, "tcp", 1) &&
	    connect(s, (struct sockaddr *)&sin, sizeof (sin))) {
		radlog(L_ERR|L_PERROR, "connect");
		return -1;
	}

	if (sendmsg(s, &msg, 0) < 0) {
		radlog(L_ERR|L_PERROR, "sendmsg");
		close(s);
		return -1;
	}

	obstack_init(&stk);

	/*
	 * Read from the remote system; If no data arrives, we will exit
	 * by alarm.
	 *
	 * All high bits get stripped, newlines are skipped.
	 */
	lastc = 0;
	if ((fp = fdopen(s, "r")) != NULL) {
		if (setjmp(to_env)) {
			radlog(L_NOTICE,
			       _("timed out in waiting for finger response from NAS %s"),
			       checkp->hostname);
			fclose(fp);
			obstack_free(&stk, NULL);
			alarm(0);
			signal(SIGALRM, handler);
			return checkp->result = -1;
		}

		to = ilookup(checkp, "timeout", 10);
		handler = signal(SIGALRM, alrm_handler);
		alarm(to);

		while ((c = getc(fp)) != EOF) {
			if (c == 0x0d) {
				if (lastc == '\r')	/* ^M^M - skip dupes */
					continue;
				c = '\n';
				lastc = '\r';
			} else {
				if (!isprint(c) && !isspace(c)) {
					c &= 0x7f;
					c |= 0x40;
				}
				if (lastc != '\r' || c != '\n')
					lastc = c;
				else {
					lastc = '\n';
					continue;
				}
			}
			obstack_1grow(&stk, c);
			if (c == '\n') {
				/* Make sure no alarm arrives while
				 * processing data
				 */
				to = alarm(0);
				signal(SIGALRM, handler);
				
				obstack_1grow(&stk, 0);
				ptr = obstack_finish(&stk);
				debug(2,("got : %s", ptr));
				found = compare(checkp, ptr);
				obstack_free(&stk, ptr);
				if (found) 
					break;

				/* restore alarm settings */
				signal(SIGALRM, alrm_handler);
				alarm(to);
			}
		}
		
		if (!found && lastc != '\n') {
			/* Make sure no alarm arrives while
			 * processing data
			 */
			alarm(0);
			signal(SIGALRM, handler);

			obstack_1grow(&stk, '\n');
			obstack_1grow(&stk, 0);
			debug(2,("got : %s", ptr));
			ptr = obstack_finish(&stk);
			found = compare(checkp, ptr);
		}
		obstack_free(&stk, NULL);
		
		if (ferror(fp)) {
			/*
			 * Assume that whatever it was set errno...
			 */
			radlog(L_ERR|L_PERROR, "finger");
		}
		fclose(fp);
	}

        /* restore alarm settings */
	alarm(0);
	signal(SIGALRM, handler);

	debug(1, ("result: %d", found));
	checkp->result = found;
	return found;
}

int
ext_check(checkp, nas)
	struct check_instance *checkp;
	NAS *nas;
{
	radlog(L_ERR, "ext_check not implemented");
	return -1;
}

int
checkrad(nas, up)
	NAS *nas;
	struct radutmp *up;
{
	struct check_instance checkp;
	int rc = -1;
	
	if (!create_instance(&checkp, nas, up))
		return -1;

	switch (checkp.method) {
	case METHOD_FINGER:
		rc = finger_check(&checkp, nas);
		break;
	case METHOD_SNMP:
		rc = snmp_check(&checkp, nas);
		break;
	case METHOD_EXT:
		rc = ext_check(&checkp, nas);
		break;
	default:
		insist_fail("bad method");
	}
	free_instance(&checkp);
	return rc;
}
