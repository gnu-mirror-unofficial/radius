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
/*FIXME: do I need it still? */
#ifndef __radsnmp_h
#define __radsnmp_h

typedef struct snmp_req {
	struct snmp_pdu *pdu;
	char *community;
	int access;
	struct sockaddr_in sa;
} SNMP_REQ;


void snmp_req_free(SNMP_REQ *req);
void snmp_req_drop(int type, SNMP_REQ *req, char *status_str);
	

#endif



