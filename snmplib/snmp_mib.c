/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001,2003,2004,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <snmp/mib.h>

#define SCMP(node, s, op) \
(((node)->subid == SUBID_X) ? \
((*(node)->handler)(MIB_NODE_COMPARE, (node)->closure, s, NULL, NULL) \
     op 0) :\
 ((node)->subid op s))  

int
mib_lookup(struct mib_node_t *node, oid_t oid,
	   int len, struct mib_node_t **return_node)
{
        subid_t *p = OIDPTR(oid);
        int ind;
        
        for (ind = 0; ind < len; ind++) {
                while (SCMP(node, p[ind], <)) {
                        if (node->down) {
                                node = node->down;
                        } else {
                                *return_node = node;
                                return MIB_MATCH_UPPER;
                        }
                }
                if (node->next == NULL) {
                        *return_node = node;
                        break;
                }
                node = node->next;
        }
        *return_node = node;
        return (ind+1) < len ? MIB_MATCH_PREV : MIB_MATCH_EXACT;
}

int
mib_insert_node(struct mib_node_t **root_node, oid_t oid,
		int len, struct mib_node_t **return_node)
{
        int rc;
        struct mib_node_t *newp;

        *return_node = *root_node;
        if (*root_node &&
            (rc = mib_lookup(*root_node, oid, len, return_node)) ==
             MIB_MATCH_EXACT)
                return rc;

        if (!(newp = snmp_alloc(sizeof(*newp)))) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                return MIB_ERROR;
        }
        newp->next = newp->down = NULL;
        newp->index = len-1;
        newp->subid = SUBID(oid,len-1);
        newp->handler = NULL;
        if (!*root_node)
                *root_node = newp;
        else if (rc == MIB_MATCH_UPPER) {
                struct mib_node_t *p;

                newp->up = (*return_node)->up;
                if (!(*return_node)->down)
                        (*return_node)->down = newp;
                else {
                        for (p = (*return_node)->down; p->down; p = p->down)
                                ;
                        p->down = newp;
                }
        } else {
                (*return_node)->next = newp;
                newp->up = *return_node;
        }
        *return_node = newp;
        return rc;
}

int
mib_insert(struct mib_node_t **node, oid_t oid,
	   struct mib_node_t **return_node)
{
        int len = OIDLEN(oid);
        int i;
        int rc;

        *return_node = NULL;
        for (i = 1; i <= len; i++) 
                rc = mib_insert_node(node, oid, i, return_node);
        return rc;
}

