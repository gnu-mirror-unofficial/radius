/* This file is part of GNU RADIUS.
   Copyright (C) 2002, Sergey Poznyakoff
  
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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#define SERVER
#include <raduse.h>

struct mib_data *mib_data_lookup(struct mib_data *mp, oid_t oid);

/* return formatted textual description of SNMP error status */
char *
format_snmp_error_str(err_stat)
	int err_stat;
{
	switch (err_stat) {
	case SNMP_ERR_TOOBIG:
		return "packet too big";
	case SNMP_ERR_NOSUCHNAME:
		return "no such variable";
	case SNMP_ERR_BADVALUE:
		return "bad value";
	case SNMP_ERR_READONLY:
		return "variable read only";
	case SNMP_ERR_GENERR:
		return "general error";
	case SNMP_ERR_NOACCESS:
		return "variable is not accessible";
	case SNMP_ERR_WRONGTYPE:
		return "bad type for the variable";
	case SNMP_ERR_WRONGLENGTH:
		return "wrong length";
	case SNMP_ERR_WRONGENCODING:
		return "wrong encoding";
	case SNMP_ERR_WRONGVALUE:
		return "wrong value";
	case SNMP_ERR_NOCREATION:
		return "can't create";
	case SNMP_ERR_INCONSISTENTVALUE:
		return "value inconsistent";
	case SNMP_ERR_RESOURCEUNAVAILABLE:
		return "resource unavailable";
	case SNMP_ERR_COMMITFAILED:
		return "commit falied";
	case SNMP_ERR_UNDOFAILED:
		return "undo failed";
	case SNMP_ERR_AUTHORIZATIONERROR:
		return "auth failed";
	case SNMP_ERR_NOTWRITABLE:
		return "variable not writable";
	case SNMP_ERR_INCONSISTENTNAME:
		return "name inconsistent";
	}
	return "no error";
}

void
save_var(var, ptr)
	struct snmp_var *var;
	void *ptr;
{
	char **sptr;
	oid_t *oidptr;
	struct timeval *tvptr;
	struct in_addr in;
	
	switch (var->type) {
	case SMI_STRING:
		sptr = (char**)ptr;
		if (*sptr)
			efree(*sptr);
		*sptr = estrdup(var->var_str);
		break;
	case SMI_TIMETICKS:
		tvptr = (struct timeval*)ptr;
		tvptr->tv_sec = var->var_int / 100;
		tvptr->tv_usec = (var->var_int - tvptr->tv_sec*100)*10000;
		break;
	case SMI_INTEGER:
		*(unsigned*)ptr = var->var_int;
		break;
	case SMI_COUNTER32:
		*(counter*)ptr = var->var_int;
		break;
	case SMI_COUNTER64:
		break;
	case SMI_IPADDRESS:
		*(UINT4*)ptr = *(unsigned int*)var->var_str;
		break;
	case SMI_OPAQUE:
		sptr = (char**)ptr;
		if (*sptr)
			efree(*sptr);
		*sptr = emalloc(var->val_length);
		memcpy(*sptr, var->var_str, var->val_length);
		break;
	case SMI_OBJID:
		oidptr = (oid_t*)ptr;
		if (*oidptr)
			efree(*oidptr);
		*oidptr = oid_dup(var->var_oid);
		break;
	}
}

int
converse(type, sp, pdu, closure)
	int type;
	struct snmp_session *sp;
	struct snmp_pdu *pdu;
	void *closure;
{
	struct snmp_var *var;
	int ind;
	struct mib_data *mp;
	
	if (type == SNMP_CONV_TIMEOUT) {
		radlog(L_ERR, "timed out in waiting SNMP response from %s\n",
		       ip_hostname(sp->remote_sin.sin_addr.s_addr));
		/*FIXME: inform main that the timeout has occured */
		return 1;
	}

	if (type != SNMP_CONV_RECV_MSG)
		return 1;

	if (pdu->err_stat != SNMP_ERR_NOERROR) 
		printf("Error in packet: %s\n",
		       format_snmp_error_str(pdu->err_stat));
	
	for (var = pdu->var, ind = 1; var; var = var->next, ind++) {
		if (ind == pdu->err_ind) {
			char oidbuf[512];
			
			printf("this variable caused error: %s\n",
			       sprint_oid(oidbuf, sizeof oidbuf, var->name));
			break;
		}

		mp = mib_data_lookup(closure, var->name);
		if (mp) 
			save_var(var, mp->closure);
	}
						
	return 1;
}

struct mib_data *
mib_data_lookup(mp, oid)
	struct mib_data *mp;
	oid_t oid;
{
	for (; mp->oid; mp++)
		if (oid_cmp(mp->oid, oid) == 0)
			return mp;
	return NULL;
}

void
run_query(mp)
	struct mib_data *mp;
{
	int i;
	struct snmp_session *session;
	struct snmp_pdu *pdu;
	struct snmp_var *var;
	
	session = snmp_session_create(community, hostname, port, converse, mp);
	if (!session) {
		radlog(L_CRIT, "(session) snmp err %d\n", snmp_errno);
		exit(1);
	}

	pdu = snmp_pdu_create(SNMP_PDU_GET);
	if (!pdu) {
		radlog(L_ERR, "(pdu) snmp err %d\n", snmp_errno);
		return;
	}
	
	for (; mp->oid; mp++) {
		var = snmp_var_create(mp->oid);
		if (!var) {
			radlog(L_ERR, "(var) snmp err %d\n", snmp_errno);
			continue;
		}
		snmp_pdu_add_var(pdu, var);
	}

	if (snmp_query(session, pdu)) {
		fprintf(stderr, "(snmp_query) snmp err %d\n", snmp_errno);
		return;
	}
	snmp_session_close(session);
}

char *
format_time(tv, buffer, size)
	struct timeval *tv;
	char *buffer;
	int size;
{
	long timeticks;
	int centisecs, seconds, minutes, hours, days;

	timeticks = tv->tv_sec;
	days = timeticks / (60 * 60 * 24);
	timeticks %= (60 * 60 * 24);

	hours = timeticks / (60 * 60);
	timeticks %= (60 * 60);

	minutes = timeticks / 60;
	seconds = timeticks % 60;

	centisecs = tv->tv_usec / 10000;
	snprintf(buffer, size, "%d:%02d:%02d:%02d.%02d",
		 days, hours, minutes, seconds, centisecs);
	return buffer;
}

