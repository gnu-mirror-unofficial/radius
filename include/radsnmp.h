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

#ifndef __radsnmp_h
#define __radsnmp_h

typedef struct snmp_req {
	struct snmp_pdu *pdu;
	char *community;
	int access;
	struct sockaddr_in sa;
} SNMP_REQ;

typedef struct mib_tree_node Mib_tree_node;

typedef variable_list *(*oid_pf)(variable_list *, int *);
typedef variable_list *(*oid_sf)(variable_list *, int *);

typedef Mib_tree_node *(*oid_gf)(Mib_tree_node *, oid *, int);

struct mib_tree_node {
	oid *name;
	int len;
	oid_pf parser;
	oid_sf set;
	oid_gf get;
	oid_gf getnext;
	int numchildren;
	Mib_tree_node *parent, *son, *brother;
};

void snmp_build_acct_tree();
void snmp_req_free(SNMP_REQ *req);
void snmp_req_drop(int type, SNMP_REQ *req, char *status_str);
	
oid_pf snmp_tree_pf(Mib_tree_node *, oid *, int);
oid_sf snmp_tree_sf(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_auth_getnext(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_auth_get(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_acct_getnext(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_acct_get(Mib_tree_node *, oid *, int);

variable_list * snmp_acct_var(variable_list *, int *);
variable_list * snmp_acct_client_var(variable_list *, int *);
variable_list * snmp_acct_compliance(variable_list *, int *);
variable_list * snmp_acct_mib_group(variable_list *, int *);
variable_list * snmp_acct_set(variable_list *, int *);

variable_list * snmp_auth_var(variable_list *, int *);
variable_list * snmp_auth_client_var(variable_list *, int *);
variable_list * snmp_auth_compliance(variable_list *, int *);
variable_list * snmp_auth_mib_group(variable_list *, int *);
variable_list * snmp_auth_set(variable_list *, int *);

variable_list * snmp_stat_var(variable_list *, int *);
variable_list * snmp_stat_client_var(variable_list *, int *);
Mib_tree_node * snmp_stat_getnext(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_stat_get(Mib_tree_node *, oid *, int);

variable_list * snmp_stat_port_var(variable_list *, int *);
Mib_tree_node * snmp_stat_port_get(Mib_tree_node *, oid *, int);
Mib_tree_node * snmp_stat_port_getnext(Mib_tree_node *, oid *, int);

#endif



