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

#define RADIUS_MODULE 13
#ifndef lint
static char rcsid[] = 
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/in.h>
#if defined(sun)
# include <fcntl.h>
#endif
#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <log.h>

#ifdef USE_SNMP
struct radstat radstat;
#endif
PORT_STAT *stat_base;
unsigned maxstat = STAT_MAX_PORT_COUNT * STAT_MAX_NAS_COUNT;

#ifdef USE_SNMP
void
stat_init()
{
	struct timeval tv;
	struct timezone tz;

	if (shmem_alloc(STAT_MAX_PORT_COUNT * sizeof(PORT_STAT) +
			sizeof(*server_stat) +
			STAT_MAX_NAS_COUNT * sizeof(struct nas_stat))) {
		radlog(L_CRIT, _("stat_init failed"));
		exit(1);
	}

	stat_base   = shmem_get(STAT_MAX_PORT_COUNT * sizeof(PORT_STAT), 0);

	server_stat = shmem_get(sizeof(*server_stat) +
				STAT_MAX_NAS_COUNT * sizeof(struct nas_stat),
				1);
	
	gettimeofday(&tv, &tz);
	server_stat->start_time = tv;
	server_stat->auth.reset_time = tv;
	server_stat->acct.reset_time = tv;	
	server_stat->auth.status = serv_running;
	server_stat->acct.status = serv_running;
}
#else
void
stat_init()
{
	if (shmem_alloc(STAT_MAX_PORT_COUNT * sizeof(PORT_STAT))) {
		radlog(L_CRIT, _("stat_init failed"));
		exit(1);
	}
	stat_base   = shmem_get(STAT_MAX_PORT_COUNT * sizeof(PORT_STAT), 0);
}
#endif

void
stat_done()
{
	shmem_free();
}

void
stat_create()
{
	PORT_STAT *port;

	if (!stat_base) 
		return;
	
	if (stat_base->start == 0) {
		stat_base->start = time(NULL);
	}
#ifdef USE_SNMP
	radstat.start_time.tv_sec = stat_base->start;
	radstat.start_time.tv_usec = 0;
#endif

	if (debug_on(2)) {
		for (port = stat_base + 1; port < stat_base + 1 + maxstat; port++) {
			if (port->ip == 0)
				break;
			
			debug(2, ("read NAS %#x port %d",
				     port->ip, port->port_no));
		}
	}
}

PORT_STAT *
stat_alloc_port()
{
	PORT_STAT *port;
	
	for (port = stat_base + 1; port < stat_base + 1 + maxstat; port++) {
		if (port->ip == 0)
			return port;
	}
	return NULL;
}

PORT_STAT *
stat_find_port(nas, port_no)
	NAS *nas;
	int port_no;
{
	PORT_STAT *port;
	
	for (port = stat_base + 1; port < stat_base + 1 + maxstat; port++) {
		if (port->ip == 0)
			break;
		if (port->ip == nas->ipaddr && port->port_no == port_no)
			return port;
	}

	/* Port not found */
	if ((port = stat_alloc_port()) == NULL) {
		radlog(L_ERR,
		    _("can't allocate port_stat: increase maxstat and recompile"));
		return NULL;
	}
	port->ip = nas->ipaddr;
	port->port_no = port_no;
	
	debug(1, ("next offset %d", port - stat_base));

	return port;
}


void
stat_update(ut, status)
	struct radutmp *ut;
	int status;
{
	NAS *nas;
	PORT_STAT *port;
	char ipbuf[DOTTED_QUAD_LEN];
	long dt;
	
	nas = nas_find(ntohl(ut->nas_address));
	if (!nas) {
		radlog(L_WARN,
		    _("stat_update(): portno %d: can't find nas for IP %s"),
		    ut->nas_port,
		    ipaddr2str(ipbuf, ntohl(ut->nas_address)));
		return;
	}

	port = stat_find_port(nas, ut->nas_port);
	if (!port) {
		radlog(L_WARN,
		    _("stat_update(): port %d not found on NAS %s"),
		    ut->nas_port,
		    ipaddr2str(ipbuf, ntohl(ut->nas_address)));
		return;
	}

	switch (status) {
	case DV_ACCT_STATUS_TYPE_START:
		if (port->start) {
			dt = ut->time - port->start;
			if (dt < 0) {
				radlog(L_NOTICE,
				    _("stat_update(START,%s,%s,%d): negative time skew"),
				    ut->login, nas->shortname, ut->nas_port);
			} else {
				port->idle += dt;
			}
			if (dt > port->maxidle.time) {
				port->maxidle.time = dt;
				port->maxidle.start = port->start;
			}
		}
		
		strncpy(port->login, ut->login, sizeof(port->login));
		port->framed_address = ut->framed_address;
		port->active = 1;
		port->count++;
		port->start = port->lastin = ut->time;
		break;
		
	case DV_ACCT_STATUS_TYPE_STOP:
		if (port->start) {
			dt = ut->time - port->start;
			if (dt < 0) {
				radlog(L_NOTICE,
				    _("stat_update(STOP,%s,%s,%d): negative time skew"),
				    ut->login, nas->shortname, ut->nas_port);
			} else {
				port->inuse += dt;
			}
			if (dt > port->maxinuse.time) {
				port->maxinuse.time = dt;
				port->maxinuse.start = port->start;
			}
		}
		
		port->active = 0;
		port->start = port->lastout = ut->time;
		break;

	case DV_ACCT_STATUS_TYPE_ALIVE:
		strncpy(port->login, ut->login, sizeof(port->login));
		port->framed_address = ut->framed_address;
		port->active = 1;
		break;
	}

	debug(1,
		("NAS %#x port %d: act %d, cnt %d, start %d, inuse %d/%d idle %d/%d",
		 port->ip, port->port_no, port->active,
		 port->count, port->start,
		 port->inuse, port->maxinuse.time,
		 port->idle, port->maxidle.time));
}

#ifdef USE_SNMP
void
stat_count_ports()
{
	NAS *nas;
	PORT_STAT *port;
	extern NAS *naslist;
	
	for (nas = naslist; nas; nas = nas->next) {
		nas->nas_stat->ports_active = nas->nas_stat->ports_idle = 0;
	}
	
	radstat.port_active_count = radstat.port_idle_count = 0;

	for (port = stat_base + 1; port < stat_base + 1 + maxstat; port++) {
		if (port->ip == 0)
			break;

		nas = nas_find(port->ip);
		if (!nas) {
			/* Silently ignore */
			continue;
		}
		if (port->active) {
			nas->nas_stat->ports_active++;
			radstat.port_active_count++;
		} else {
			nas->nas_stat->ports_idle++;
			radstat.port_idle_count++;
		}
	}
}
#endif

PORT_STAT *
findportbyindex(ind)
	int ind;
{
	PORT_STAT *p;
	int i;

	for (i = 1, p = stat_base+1;
	     i < ind && p < stat_base + STAT_MAX_PORT_COUNT + 1 && p->ip;
	     i++, p++) /* empty */ ;

	if (p->ip == 0)
		return NULL;
	return p;
}

