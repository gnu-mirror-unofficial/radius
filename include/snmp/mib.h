/*
   Copyright (C) 2001, Sergey Poznyakoff.

   This file is part of GNU Radius SNMP Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#define MIB_ERROR      -1
#define MIB_SUCCESS     0
#define MIB_MATCH_EXACT 0
#define MIB_MATCH_UPPER 1
#define MIB_MATCH_PREV  2

struct mib_node_t;

enum var_subid_cmd {
	VAR_SUBID_GET,
	VAR_SUBID_SET,
	VAR_SUBID_SET_TRY,
	VAR_SUBID_COMPARE,
	VAR_SUBID_NEXT,
	VAR_SUBID_RESET
};

typedef int (*mib_fp)(enum var_subid_cmd, void *, subid_t, 
		      struct snmp_var **, int *);

struct mib_node_t {
	struct mib_node_t *up, *down, *next;
	subid_t subid;
	int index;
	mib_fp handler;
	void *closure;
};

#define SUBID_X (subid_t)-1

int mib_lookup(struct mib_node_t *node, oid_t oid, int len,
	       struct mib_node_t **return_node);
int mib_insert_node(struct mib_node_t **root_node, oid_t oid, int len,
		    struct mib_node_t **return_node);
int mib_insert(struct mib_node_t **node, oid_t oid,
	       struct mib_node_t **return_node);


	
