/* This file is part of GNU RADIUS.
 * Copyright (C) 2000,2001, Sergey Poznyakoff
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

#define RADIUS_MODULE_CHECKRAD_C

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

#include <asn1.h>
#include <snmp.h>

struct check_instance {
	char      *name;
	int       port;
	char      *sid;
	UINT4     ip;
	int       result;
	int       timeout;
	int       method;
	char      *func;
	envar_t   *args;
	char      *hostname;
};

struct check_instance * create_instance(struct check_instance *cptr,
					NAS *nas, struct radutmp *up);
void free_instance(struct check_instance *cptr);
char * slookup(struct check_instance *checkp, char *name, char *defval);
int ilookup(struct check_instance *checkp, char *name, int defval);
int compare(struct check_instance *checkp, char *str);

struct check_instance *
create_instance(cptr, nas, up)
	struct check_instance *cptr;
	NAS *nas;
	struct radutmp *up;
{
	RADCK_TYPE *radck_type;
		
	if ((radck_type = find_radck_type(nas->nastype)) == NULL) {
		radlog(L_ERR,
		       _("unknown NAS type: %s (nas %s)"),
		       nas->nastype,
		       nas->shortname);
		return NULL;
	}
	cptr->name = up->orig_login;
	cptr->port = up->nas_port;
	cptr->sid  = up->session_id;
	cptr->ip   = up->framed_address;
	cptr->result = -1;
	cptr->timeout = 0;
	cptr->hostname = nas->shortname ? nas->shortname : nas->longname;
	
	cptr->method = radck_type->method;
	cptr->args = envar_merge_lists((envar_t*) nas->args, radck_type->args);
	cptr->func = slookup(cptr, "function", NULL);
	return cptr;
}

void
free_instance(cptr)
	struct check_instance *cptr;
{
	envar_free_list(cptr->args);
}

char *
slookup(checkp, name, defval)
	struct check_instance *checkp;
	char *name;
	char *defval;
{
	char *s;

	if (s = envar_lookup(checkp->args, name))
		return s;
	return defval;
}

int
ilookup(checkp, name, defval)
	struct check_instance *checkp;
	char *name;
	int defval;
{
	char *s;
	
	if (s = envar_lookup(checkp->args, name))
		return atoi(s);
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
				snprintf(buf, sizeof(buf), "%lu",
					   strtol(checkp->sid, NULL, 16));
				ptr = buf;
				break;
			case 'p':
				snprintf(buf, sizeof(buf), "%d", 
					checkp->port);
				ptr = buf;
				break;
			case 'P':
				snprintf(buf, sizeof(buf), "%d",
					 checkp->port + 1);
				ptr = buf;
				break;
			case 'i':
				snprintf(buf, sizeof(buf), "%s",
					   format_ipaddr(checkp->ip));
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

static int converse(int type, struct snmp_session *sp, struct snmp_pdu *pdu,
		    void *closure);

/*ARGSUSED*/
int
converse(type, sp, pdu, closure)
	int type;
	struct snmp_session *sp;
	struct snmp_pdu *pdu;
	void *closure;
{
	int rc = 0;
	struct snmp_var *vlist;
	struct check_instance *checkp = (struct check_instance *)closure;
	char buf[64];

	if (type == SNMP_CONV_TIMEOUT) {
		radlog(L_NOTICE,
		       _("timed out in waiting SNMP response from NAS %s"),
		       checkp->hostname);
		checkp->timeout++;
		return 1;
	}
	if (type != SNMP_CONV_RECV_MSG)
		return 1;

	for (vlist = pdu->var; rc == 0 && vlist; vlist = vlist->next)  
		switch (vlist->type) {
		case SMI_STRING:
			rc = compare(checkp, vlist->var_str);
			debug(2, ("(STRING) %s: %d", vlist->var_str, rc));
			break;
		case SMI_INTEGER:
		case SMI_COUNTER32:
		case SMI_COUNTER64:
			snprintf(buf, sizeof(buf), "%d", vlist->var_int);
			rc = compare(checkp, buf);
			debug(2, ("(INT) %d: %d", vlist->var_int, rc));
			break;
		case SMI_IPADDRESS:
			ipaddr2str(buf, *(UINT4*)vlist->var_int);
			rc = compare(checkp, buf);
			debug(2, ("(IPADDR) %#x: %d",
				  *(UINT4*)vlist->var_str, rc));
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
        struct snmp_session *sp;
	struct snmp_var *var;
	char *community;
	int retries;
	int timeout;
	char *peername;
	int remote_port;
	oid_t oid;
	char *snmp_oid;
	
	if ((snmp_oid = slookup(checkp, "oid", NULL)) == NULL) {
		radlog(L_ERR, _("no snmp_oid"));
		return -1;
	}
	snmp_oid = checkrad_xlat(checkp, snmp_oid);
	oid = oid_create_from_string(snmp_oid);
	if (!oid) {
		radlog(L_ERR,
		       _("invalid OID: %s"), snmp_oid);
		efree(snmp_oid);
		return -1;
	}
	
	if ((community = slookup(checkp, "password", NULL)) == NULL &&
	    (community = slookup(checkp, "community", NULL)) == NULL)
		community = "public";

	retries = ilookup(checkp, "retries", 3);
	timeout = ilookup(checkp, "timeout", 2);
	peername = slookup(checkp, "host", nas->longname);
	remote_port = ilookup(checkp, "port", 161);

	sp = snmp_session_create(community, peername, remote_port, 
				 converse, checkp);
	if (!sp) {
		radlog(L_ERR,
		       _("can't create snmp session: %s"),
			 snmp_strerror(snmp_errno));
		efree(snmp_oid);
		snmp_free(oid);
		return -1;
	}
	
	if (snmp_session_open(sp, myip, 0, timeout, retries)) {
		radlog(L_ERR,
		       _("can't open snmp session: %s"),
			 snmp_strerror(snmp_errno));
		efree(snmp_oid);		
		snmp_free(oid);
		return -1;
	}

	if ((pdu = snmp_pdu_create(SNMP_PDU_GET)) == NULL) {
		radlog(L_ERR,
		       _("can't create SNMP PDU: %s"),
			 snmp_strerror(snmp_errno));
		efree(snmp_oid);
		snmp_free(oid);
		snmp_session_close(sp);
		return -1;
	}
		
	if ((var = snmp_var_create(oid)) == NULL) {
		radlog(L_ERR,
		       _("can't create SNMP PDU: %s"),
			 snmp_strerror(snmp_errno));
		efree(snmp_oid);
		snmp_free(oid);
		snmp_session_close(sp);
		snmp_pdu_free(pdu);
		return -1;
	}

	snmp_pdu_add_var(pdu, var);
	snmp_free(oid);

	debug(1, ("snmpget: %s:%d %s %s",
		  peername,
		  remote_port,
		  community,
		  snmp_oid));

	efree(snmp_oid);

	checkp->result = rc;
	
	snmp_query(sp, pdu);

	rc = checkp->result;
	snmp_session_close(sp);
	
	debug(1, ("result: %d", rc));
	return rc;
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
	char *peername;
	struct obstack stk;
	char *ptr;
	RETSIGTYPE (*handler)() = SIG_IGN;
	unsigned int to;
	
	/* Copy at most RUT_NAMESIZE bytes from the user name */
	ptr = checkp->name;
	for (i = 0; i < RUT_NAMESIZE && *ptr; ++ptr, ++i)
		namebuf[i] = *ptr;
	namebuf[i] = 0;
	namelen = i;

	peername = slookup(checkp, "host", nas->longname);
	if (!(hp = gethostbyname(peername))) {
		radlog(L_ERR, _("unknown host: %s"), peername);
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
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof sin;
	msg.msg_iov = iov;
	msg.msg_iovlen = 0;
	
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

/*ARGSUSED*/
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

