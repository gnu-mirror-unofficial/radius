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
#define RADIUS_MODULE 12
#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>

#include "radiusd.h"
#include "ippool.h"

IP_POOL *
alloc_pool(start_ip, ip_cnt, start_port)
	UINT4 start_ip;
	int ip_cnt;
	int start_port;
{
	int i;
	IP_POOL *p;
	struct ip_cell *ip;
	int size = sizeof(IP_POOL) + (ip_cnt-1) * sizeof(struct ip_cell);

	p = emalloc(size);
	p->cnt = ip_cnt;
	ip = p->ip;
	for (i = 0; i < ip_cnt; i++, ip++, start_port++, start_ip++) {
		ip->port = start_port;
		ip->addr = start_ip;
	}
	return p;
}

void
free_pool(ptr)
	IP_POOL *ptr;
{
	if (ptr)
		efree(ptr);
}

UINT4
alloc_ip(nas, port)
	NAS *nas;
	int port;
{
	int i;
	IP_POOL *p;
	struct ip_cell *ip;

	if ((p = nas->ip_pool) == NULL)
		return 0;
	ip = p->ip;
	for (i = 0; i < p->cnt; i++, ip++) {
		if (ip->port == port)
			return ip->addr;
	}
	return 0;
}


VALUE_PAIR *
alloc_ip_pair(name, authreq)
	char *name;
	AUTH_REQ *authreq;
{
	UINT4	ipaddr;
	NAS	*nas;
	VALUE_PAIR	*pair = NULL;
	int port;
	char ipbuf[DOTTED_QUAD_LEN];
	
	if ((pair = pairfind(authreq->request, DA_NAS_IP_ADDRESS)) != NULL)
		ipaddr = pair->lvalue;
	else
		ipaddr = authreq->ipaddr;

	if ((nas = nas_find(ipaddr)) == NULL) {
		debug(1,("can't find nas?"));
		return NULL;
	}
	
	if (nas->ip_pool == NULL)
		return NULL;

	if ((pair = pairfind(authreq->request, DA_NAS_PORT_ID)) != NULL)
		port = pair->lvalue;
	else {
		radlog(L_WARN, _("alloc_ip_pair(): no NAS-Port-Id attribute"));
		return NULL;
	}

	ipaddr = alloc_ip(nas, port);
	if (ipaddr) {
		debug(1, ("%s: port %d IP %s",
		     name, port, ipaddr2str(ipbuf, ipaddr)));
		pair = create_pair(DA_FRAMED_IP_ADDRESS, 0, NULL, ipaddr);
	}
	return pair;
}









