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
#define RADIUS_MODULE 15
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#ifdef USE_SNMP

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <varargs.h>
#include <asn1.h>
#include <snmp.h>
#include <mib.h>

#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <radsnmp.h>
#define SERVER
#include <radmibs.h>

#define MAXOIDLEN 512

struct snmp_pdu * snmp_agent_response(struct snmp_pdu *pdu, int access);

int snmp_decode(SNMP_REQ *req, u_char *buf, int len);

int variable_cmp(struct snmp_var *v1, struct snmp_var *v2);

ACL *snmp_acl, *snmp_acl_tail;
Community *commlist, *commlist_tail;
Server_stat *server_stat;
extern PORT_STAT *stat_base;


/* ************************************************************************ */
/* ACL fiddling */

void
snmp_add_community(str, access)
	char *str;
	int access;
{
	Community *p = alloc_entry(sizeof(*p));
	p->name = estrdup(str);
	p->access = access;
	if (commlist_tail)
		commlist_tail->next = p;
	else
		commlist = p;
	commlist_tail = p;
}

Community *
snmp_find_community(str)
	char *str;
{
	Community *p;

	for (p = commlist; p; p = p->next)
		if (strcmp(p->name, str) == 0)
			return p;
	return NULL;
}

void
snmp_free_communities()
{
	Community *p = commlist, *next;
	while (p) {
		next = p->next;
		efree(p->name);
		free_entry(p);
		p = next;
	}
	commlist = commlist_tail = NULL;
}

int
check_acl(ip, community)
	UINT4 ip;
	char *community;
{
	ACL *acl;

	for (acl = snmp_acl; acl; acl = acl->next) {
		if (acl->ipaddr == (ip & acl->netmask)) {
			if (!acl->community)
				return 0;
			else if (strcmp(acl->community->name, community) == 0)
				return acl->community->access;
		}
	}
	return 0;
}

void
snmp_add_acl(acl, community)
	ACL *acl;
	Community *community;
{
	ACL *new_acl;
	
	for (; acl; acl = acl->next) {
		new_acl = alloc_entry(sizeof(*new_acl));
		memcpy(new_acl, acl, sizeof(ACL));
		new_acl->community = community;
		if (snmp_acl_tail)
			snmp_acl_tail->next = new_acl;
		else
			snmp_acl = new_acl;
		snmp_acl_tail = new_acl;
	}
}

void
snmp_free_acl()
{
	free_acl(snmp_acl);
	snmp_acl = snmp_acl_tail = NULL;
}

void
free_acl(acl)
	ACL *acl;
{
	ACL *next;

	while (acl) {
		next = acl->next;
		free_entry(acl);
		acl = next;
	}
}

/* ************************************************************************ */
/* Application-specific */

struct mib_node_t *mib_tree;
int snmp_auth_handler(enum var_subid_cmd cmd, void *closure, subid_t subid,
		      struct snmp_var **varp, int *errp);
int snmp_auth_v_handler(enum var_subid_cmd cmd, void *closure, subid_t subid,
			struct snmp_var **varp, int *errp);
int snmp_acct_handler(enum var_subid_cmd cmd, void *closure, subid_t subid,
		      struct snmp_var **varp, int *errp);
int snmp_acct_v_handler(enum var_subid_cmd cmd, void *closure, subid_t subid,
			struct snmp_var **varp, int *errp);

static struct mib_data {
	oid_t oid;
	mib_fp handler;
	void *closure;
} mib_data[] = {
	/* Authentication */
	/* Fixed oids */
	oid_AuthServIdent,                   snmp_auth_handler, NULL,
	oid_AuthServUpTime,                  snmp_auth_handler, NULL,
	oid_AuthServResetTime,               snmp_auth_handler, NULL,
	oid_AuthServConfigReset,             snmp_auth_handler, NULL,
	oid_AuthServTotalAccessRequests,     snmp_auth_handler, NULL,
	oid_AuthServTotalInvalidRequests,    snmp_auth_handler, NULL,
	oid_AuthServTotalDupAccessRequests,  snmp_auth_handler, NULL,
	oid_AuthServTotalAccessAccepts,      snmp_auth_handler, NULL,
	oid_AuthServTotalAccessRejects,      snmp_auth_handler, NULL,
	oid_AuthServTotalAccessChallenges,   snmp_auth_handler, NULL, 
	oid_AuthServTotalMalformedAccessRequests,
	                                     snmp_auth_handler, NULL,
	oid_AuthServTotalBadAuthenticators,  snmp_auth_handler, NULL,
	oid_AuthServTotalPacketsDropped,     snmp_auth_handler, NULL,
	oid_AuthServTotalUnknownTypes,       snmp_auth_handler, NULL,

	/* Variable oids */
	oid_AuthClientIndex,                 snmp_auth_v_handler, NULL,
	oid_AuthClientAddress,               snmp_auth_v_handler, NULL,      
	oid_AuthClientID,                    snmp_auth_v_handler, NULL,      
	oid_AuthServAccessRequests,          snmp_auth_v_handler, NULL,      
	oid_AuthServDupAccessRequests,       snmp_auth_v_handler, NULL,      
	oid_AuthServAccessAccepts,           snmp_auth_v_handler, NULL,      
	oid_AuthServAccessRejects,           snmp_auth_v_handler, NULL,      
	oid_AuthServAccessChallenges,        snmp_auth_v_handler, NULL,      
	oid_AuthServMalformedAccessRequests, snmp_auth_v_handler, NULL,      
	oid_AuthServBadAuthenticators,       snmp_auth_v_handler, NULL,      
	oid_AuthServPacketsDropped,          snmp_auth_v_handler, NULL,      
	oid_AuthServUnknownTypes,            snmp_auth_v_handler, NULL,

	/* Accounting */
	/* Fixed oids */
	oid_AccServIdent,                    snmp_acct_handler, NULL,
	oid_AccServUpTime,                   snmp_acct_handler, NULL,       
	oid_AccServResetTime,                snmp_acct_handler, NULL,      
	oid_AccServConfigReset,              snmp_acct_handler, NULL,      
	oid_AccServTotalRequests,            snmp_acct_handler, NULL,      
	oid_AccServTotalInvalidRequests,     snmp_acct_handler, NULL,      
	oid_AccServTotalDupRequests,         snmp_acct_handler, NULL,      
	oid_AccServTotalResponses,           snmp_acct_handler, NULL,      
	oid_AccServTotalMalformedRequests,   snmp_acct_handler, NULL,      
	oid_AccServTotalBadAuthenticators,   snmp_acct_handler, NULL,      
	oid_AccServTotalPacketsDropped,      snmp_acct_handler, NULL,      
	oid_AccServTotalNoRecords,           snmp_acct_handler, NULL,      
	oid_AccServTotalUnknownTypes,        snmp_acct_handler, NULL,      

	/* Variable oids */
	oid_AccClientIndex,                  snmp_acct_v_handler, NULL,      
	oid_AccClientAddress,                snmp_acct_v_handler, NULL,
	oid_AccClientID,                     snmp_acct_v_handler, NULL,
	oid_AccServPacketsDropped,           snmp_acct_v_handler, NULL,
	oid_AccServRequests,                 snmp_acct_v_handler, NULL,
	oid_AccServDupRequests,              snmp_acct_v_handler, NULL,
	oid_AccServResponses,                snmp_acct_v_handler, NULL,
	oid_AccServBadAuthenticators,        snmp_acct_v_handler, NULL,
	oid_AccServMalformedRequests,        snmp_acct_v_handler, NULL,
	oid_AccServNoRecords,                snmp_acct_v_handler, NULL,
	oid_AccServUnknownTypes,             snmp_acct_v_handler, NULL,

};					    
					    
void
snmp_tree_init()
{
	struct mib_data *p;
	struct mib_node_t *node;
	
	snmp_init(0, 0, (snmp_alloc_t)emalloc, (snmp_free_t)efree);

	for (p = mib_data; p < mib_data + NITEMS(mib_data); p++) {
		mib_insert(&mib_tree, p->oid, &node);
		if (p->handler) {
			node->handler = p->handler;
			node->closure = p->closure;
		}
	}
}

/* For a given ip_address return NAS statistics info associated with it.
   if no NAS with this address is known, return NULL */
struct nas_stat *
find_nas_stat(ip_addr)
	UINT4 ip_addr;
{
	int i;
	struct nas_stat *nasstat = (struct nas_stat *)(server_stat + 1);
	
	for (i = 0; i < server_stat->nas_count; i++, nasstat++)
		if (nasstat->ipaddr == ip_addr)
			return nasstat;
	return NULL;
}

struct nas_stat *
snmp_nasstat(num)
	int num;
{
	return (struct nas_stat *)(server_stat + 1) + num;
}

void
snmp_init_nas_stat()
{
	server_stat->nas_index = 1;
}

/* Attach NAS stat info to a given NAS structure. FIXME: master is 1 if called
   from a master process: probably can be eliminated */ 
void
snmp_attach_nas_stat(nas, master)
	NAS *nas;
	int master;
{
	struct nas_stat *nasstat;

	nasstat = find_nas_stat(nas->ipaddr);
	if (!nasstat) {
		if (server_stat->nas_count >= STAT_MAX_NAS_COUNT) {
			radlog(L_ERR,
			       _("too many NASes: increase STAT_MAX_NAS_COUNT"));
			return;
		}
		nasstat = snmp_nasstat(server_stat->nas_count++);
		nasstat->ipaddr = nas->ipaddr;
	}
	if (master)
		nasstat->index = server_stat->nas_index++;
	nas->nas_stat = nasstat;
}

/* Mark reset of the auth server. Do not do any real work, though.
 */
void
snmp_auth_server_reset()
{
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	server_stat->auth.reset_time = tv;
}

/* Mark reset of the acct server. Again, no real work, please.
 */
void
snmp_acct_server_reset()
{
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	server_stat->acct.reset_time = tv;
}

static int		i_send_buffer[1024];
static char		*send_buffer = (char *)i_send_buffer;

/* Create and return SNMP request structure */
SNMP_REQ *
rad_snmp_respond(buf, len, sa)
	u_char *buf;
	int len;
	struct sockaddr_in *sa;
{
	SNMP_REQ *req;
	char ipbuf[DOTTED_QUAD_LEN];

	req = alloc_entry(sizeof *req);
	req->sa = *sa;

	debug(1,
		("got %d bytes from %I",
		 len,
		 ntohl(req->sa.sin_addr.s_addr)));
	
	if (snmp_decode(req, buf, len)) {
		free_entry(req);
		req = NULL;
	}
	return req;
}

/* Decode the SNMP request */
int
snmp_decode(req, buf, len)
	SNMP_REQ *req;
	u_char *buf;
	int len;
{
	struct snmp_pdu *pdu;
	struct snmp_session sess;
	int access;
	char ipbuf[DOTTED_QUAD_LEN];
	char comm[128];
	int comm_len;
	
	if ((pdu = snmp_pdu_create(0)) == NULL) {
		radlog(L_ERR,
		       _("can't create SNMP PDU: %s"),
			 snmp_strerror(snmp_errno));
		return -1;
	}
	comm_len = sizeof(comm);
	if (snmp_decode_request(&sess, pdu, buf, len, comm, &comm_len)) {
		radlog(L_ERR,
		       _("can't decode SNMP packet from %s: %s"),
			 ip_hostname(ntohl(req->sa.sin_addr.s_addr)),
			 snmp_strerror(snmp_errno));
		return -1;
	}

	access = check_acl(req->sa.sin_addr.s_addr, comm);
	if (!access) {
		radlog(L_NOTICE,
		       _("DENIED attempt to access community %s from %s (%I)"),
		       comm,
		       ip_hostname(ntohl(req->sa.sin_addr.s_addr)),
		       ntohl(req->sa.sin_addr.s_addr));
		return 1;
	}
	req->pdu = pdu;
	req->community = estrdup(comm);
	req->access = access;
	return 0;
}

/* Compare two SNMP requests */
int
snmp_req_cmp(a, b)
	SNMP_REQ *a, *b;
{
	return !(a->sa.sin_addr.s_addr == b->sa.sin_addr.s_addr &&
		 a->pdu->req_id == b->pdu->req_id);
}

/* Free the SNMP request */
void
snmp_req_free(req)
	SNMP_REQ *req;
{
	snmp_pdu_free(req->pdu);
	efree(req->community);
	free_entry(req);
}

void
snmp_req_drop(type, req, status_str)
	int type;
	SNMP_REQ *req;
	char *status_str;
{
	radlog(L_NOTICE,
	       _("Dropping SNMP request from client %I: %s"),
	       ntohl(req->sa.sin_addr.s_addr),
	       status_str);
}

/* Answer the request */
int
snmp_answer(req, sock)
	SNMP_REQ *req;
	int sock;
{
	struct snmp_session session;
	struct snmp_pdu *pdu;
	int len;

	pdu = snmp_agent_response(req->pdu, req->access);
	if (pdu) {
		session.version = SNMP_VERSION_1;
		session.community.str = req->community;
		session.community.len = strlen(req->community);
		len = sizeof(i_send_buffer);
		if (snmp_encode_request(&session, pdu, send_buffer, &len)==0) {
			sendto(sock,
			       send_buffer, len,
			       0, (struct sockaddr *) &req->sa,
			       sizeof(req->sa));
		}
		snmp_pdu_free(pdu);
	}
	return 0;
}

/* ************************************************************************* */
/* FIXME: these belong to snmp_mib.c */

int mib_get(struct mib_node_t *node, struct snmp_var **varp,
	    int *errp);
int mib_get_next(struct mib_node_t *node, struct snmp_var **varp,
		 int *errp);
int mib_set_try(struct mib_node_t *node, struct snmp_var **varp,
		int *errp);
int mib_set(struct mib_node_t *node, struct snmp_var **varp);
oid_t mib_node_oid(struct mib_node_t *node);

/* For a given node generate its oid. Note: When not needed anymore, the
   oid should be freed by snmp_free */
oid_t 
mib_node_oid(node)
	struct mib_node_t *node;
{
	oid_t oid;
	int i;
	
	oid = oid_create(node->index+1);
	if (!oid)
		return oid;
	for (i = node->index; node && i >= 0; i--, node = node->up) 
		SUBID(oid,i) = node->subid;
	return oid;
}

/* Get next node.
   Input:  node -- root node to start search from
           varp[0][0] -- Variable to start from
   Output: varp[0][0] -- Next variable (with its value)
           errp[0]    -- Error status
   Return: 0 -- OK */	     
int
mib_get_next(node, varp, errp)
	struct mib_node_t *node;
	struct snmp_var **varp;
	int *errp;
{
	int rc;
	oid_t oid = (*varp)->name;
	char buf[MAXOIDLEN];
	struct snmp_var *temp_var;
	struct mib_node_t *found_node;
	
	debug(2, ("OID %s",
		  sprint_oid(buf, sizeof(buf), (*varp)->name)));
	
	/* first, find the node itself */
 	rc = mib_lookup(node, oid, OIDLEN(oid), &found_node);

	*errp = SNMP_ERR_NOERROR;

	do {
		if (found_node->down == NULL && found_node->next == NULL) {
			node = NULL;
		} else {
			int depth = 0;
			node = found_node;
			while (node) {
				if (depth++ && node->handler)
					break;
				
				if (node->next)
					node = node->next;
				else
					node = node->down;
			}
		}
		
		if (!node) {
			/* The subtree is exhausted. Roll back until we find
			   first non-traversed down link */
			while (node = found_node->up) {
				if (node->down && node->down != found_node)
					break;
				found_node = node;
			}

			if (node)
				node = node->down;

		}

		found_node = node;

	} while (found_node && found_node->handler == NULL);

	if (!found_node || !found_node->handler) {
		*errp = SNMP_ERR_NOSUCHNAME;
		return -1;
	}
		
	oid = mib_node_oid(found_node);
	temp_var = snmp_var_create(oid);
	snmp_free(oid);

	debug(2, ("NXT %s",
		  sprint_oid(buf, sizeof(buf),
			     temp_var->name)));
			 
	*varp = temp_var;
	(*node->handler)(VAR_SUBID_GET, found_node->closure,
			 SUBID(temp_var->name,OIDLEN(temp_var->name)-1),
			 varp, errp);
	snmp_var_free(temp_var);
	return 0;
}

/* Get the value of a given variable
   Input:  node -- root node to start search from
           varp[0][0] -- Variable to look for
   Output: varp[0][0] -- Variable with value (not the same as on input!) 
           errp[0]    -- Error status
   Return: 0 -- OK */	     
int
mib_get(node, varp, errp)
	struct mib_node_t *node;
	struct snmp_var **varp;
	int *errp;
{
	int rc;
	oid_t oid = (*varp)->name;
	
	if ((rc = mib_lookup(node, oid, OIDLEN(oid), &node)) !=
	    MIB_MATCH_EXACT || !node->handler) {
		*errp = SNMP_ERR_NOSUCHNAME;
		return -1;
	}

	return (*node->handler)(VAR_SUBID_GET, node->closure,
				SUBID(oid,OIDLEN(oid)-1),
				varp, errp);
}

/* Check if a variable can be set
   Input: node -- tree node to start from
          varp[0][0] -- variable to look for
   Output:errp -- error status
   Return: 0 -- OK */
int
mib_set_try(node, varp, errp)
	struct mib_node_t *node;
	struct snmp_var **varp;
	int *errp;
{
	int rc;
	oid_t oid = (*varp)->name;
	
	if ((rc = mib_lookup(node, oid, OIDLEN(oid), &node)) !=
	    MIB_MATCH_EXACT || !node->handler) {
		*errp = SNMP_ERR_NOSUCHNAME;
		return -1;
	}
	
	if ((*node->handler)(VAR_SUBID_SET_TRY, node->closure,
			     SUBID(oid,OIDLEN(oid)-1),
			     varp, errp) != 0) 
		return -1;
	return 0;
}

/* Set a variable to the new value. The fuction must be called only
   when previous call to mib_set_try returned OK, so only rudimentary
   error checking is done.
   Input: node -- tree node to start from
          varp[0][0] -- variable to be set
   Return: 0 -- OK */
int
mib_set(node, varp)
	struct mib_node_t *node;
	struct snmp_var **varp;
{
	int rc;
	oid_t oid = (*varp)->name;
	
	if ((rc = mib_lookup(node, oid, OIDLEN(oid), &node)) !=
	    MIB_MATCH_EXACT || !node->handler) {
		return -1;
	}
	
	return (*node->handler)(VAR_SUBID_SET, node->closure,
				SUBID(oid,OIDLEN(oid)-1),
				varp, NULL);
}

/* ************************************************************************* */

/* Generate response PDU for a given request.
   Input: pdu -- Request pdu
          access -- Access rights
   Return:Response PDU, NULL on error */	  
struct snmp_pdu *
snmp_agent_response(pdu, access)
	struct snmp_pdu *pdu;
	int access;
{
	struct snmp_pdu *answer = NULL;
	struct snmp_var *vp, *vnew = NULL, **vpp;
	struct snmp_var **vresp;
	int index = 0;

	if ((answer = snmp_pdu_create(SNMP_PDU_RESPONSE))) {
		answer->req_id = pdu->req_id;
		answer->err_ind = 0;
		switch (pdu->type) {

		case SNMP_PDU_SET:
			/* First, check for the consistency of
			 * the request (rfc1157, 4.1.5):
			 */
			debug(1, ("SetRequest-PDU"));
			if (access == SNMP_RO) {
				answer->err_stat = SNMP_ERR_GENERR;
				answer->err_ind = 1;
				debug(1, ("bad access mode"));
				return answer;
			}
			for (vp = pdu->var; vp; vp = vp->next) {
				index++;

				if (mib_set_try(mib_tree, &vp,
						&answer->err_stat))
					break;
			}

			if (answer->err_stat != SNMP_ERR_NOERROR) {
				answer->var = snmp_var_dup_list(pdu->var);
				answer->err_ind = index;
				debug(1, ("returning error"));
				return answer;
			}

			/* Do real work */
			vresp = &answer->var;
			/* Loop through all variables */
			for (vpp = &pdu->var;
			     *vpp;
			     vpp = &(*vpp)->next) {
				vp = *vpp;

				vnew = vp;
				mib_set(mib_tree, &vnew);

				*vresp = vnew;
				vresp = &vnew->next;
			}

			debug(1, ("success"));
			return answer;

		case SNMP_PDU_GET:
			debug(1, ("GetRequest-PDU"));

			vresp = &answer->var;
			/* Loop through all variables */
			for (vpp = &pdu->var;
			     *vpp;
			     vpp = &(*vpp)->next) {
				vp = *vpp;

				index++;

				vnew = vp;
				mib_get(mib_tree, &vnew,
					&answer->err_stat);
				
				/* Was there an error? */
				if (answer->err_stat != SNMP_ERR_NOERROR ||
				    vnew == NULL) {
					answer->err_ind = index;
					debug(1, ("returning"));
					/* preserve the rest of vars */
					*vresp = snmp_var_dup_list(vp);
					*vpp = NULL;
					return answer;
				}
				/* No error.
				 * Insert this var at the end, and move on
				 * to the next.
				 */
				*vresp = vnew;
				vresp = &vnew->next;
			}
			return answer;

		case SNMP_PDU_GETNEXT:
			debug(1, ("GetNextRequest-PDU"));

			vnew = pdu->var;
			mib_get_next(mib_tree, &vnew,
				     &answer->err_stat);

			/* Was there an error? */
			if (answer->err_stat != SNMP_ERR_NOERROR) {
				answer->err_ind = 1;
				answer->var = pdu->var;
				pdu->var = NULL;
			} else {
				answer->var = vnew;
			}
			break;
			
		default:
			snmp_pdu_free(answer);
			answer = NULL;
		}
	}
	return answer;
}

/* ************************************************************************* */

counter
timeval_diff(tva, tvb)
	struct timeval *tva, *tvb;
{
	return  (tva->tv_sec - tvb->tv_sec)*100 +
		(tva->tv_usec - tvb->tv_usec)/10000;
}

/* Compare two oids. FIXME: Probalbly can be eliminated */
int
oidcmp(a, b, len)
	subid_t *a, *b;
	int len;
{
	for (; len; len--) {
		if (*a++ != *b++)
			return len;
	}
	return 0;
}

/* Compare oids of two variable lists. Order is significant.
 * Return 0 if both lists match, 1 otherwise.
 */
int
variable_cmp(v1, v2)
	struct snmp_var *v1, *v2;
{
	while (v1) {
		if (OIDLEN(v1->name) != OIDLEN(v2->name) ||
		    oidcmp(OIDPTR(v1->name), OIDPTR(v2->name),
			   OIDLEN(v1->name)))
		    return 1;
		v1 = v1->next;
		v2 = v2->next;
	}
	return !(v1 == NULL && v2 == NULL);
}

/* ************************************************************************* */
/* Auth sub-tree */

struct snmp_var *snmp_auth_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_auth_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */
int
snmp_auth_handler(cmd, closure, subid, varp, errp)
	enum var_subid_cmd cmd;
	void *closure;
	subid_t subid;
	struct snmp_var **varp;
	int *errp;
{
	oid_t oid = (*varp)->name;
	
	switch (cmd) {
	case VAR_SUBID_GET:
		if ((*varp = snmp_auth_var_get(subid, oid, errp)) == NULL)
			return -1;
		break;
		
	case VAR_SUBID_SET:
		return snmp_auth_var_set(subid, varp, errp);
		
	case VAR_SUBID_SET_TRY:
		return snmp_auth_var_set(subid, varp, errp);
		
	case VAR_SUBID_RESET:
		break;
		
	default: /* unused: should never get there */
		abort();

	}
	
	return 0;
}

struct snmp_var *
snmp_auth_var_get(subid, oid, errp)
	subid_t subid;
	oid_t oid;
	int *errp;
{
	struct snmp_var *ret;
	struct timeval tv;
	struct timezone tz;
	char *p;
	
	ret = snmp_var_create(oid);
	*errp = SNMP_ERR_NOERROR;

	switch (subid) {
		
	case MIB_KEY_AuthServIdent:
		p = make_server_ident();
		ret->type = ASN_OCTET_STR;
		ret->val_length = strlen(p);
		ret->var_str = snmp_strdup(p);
		efree(p);
		break;

	case MIB_KEY_AuthServUpTime:
		gettimeofday(&tv, &tz);
		ret->type = SMI_TIMETICKS;
		ret->val_length = sizeof(counter);
		ret->var_int = timeval_diff(&tv, &server_stat->start_time);
		break;

	case MIB_KEY_AuthServResetTime:
		gettimeofday(&tv, &tz);
		ret->type = SMI_TIMETICKS;
		ret->val_length = sizeof(counter);
		ret->var_int = timeval_diff(&tv, &server_stat->auth.reset_time);
		break;

	case MIB_KEY_AuthServConfigReset:
		ret->type = ASN_INTEGER;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.status;
		break;

	case MIB_KEY_AuthServTotalAccessRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_access_req;
		break;

	case MIB_KEY_AuthServTotalInvalidRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_invalid_req;
		break;

	case MIB_KEY_AuthServTotalDupAccessRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_dup_req;
		break;

	case MIB_KEY_AuthServTotalAccessAccepts:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_accepts;
		break;

	case MIB_KEY_AuthServTotalAccessRejects:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_rejects;
		break;

	case MIB_KEY_AuthServTotalAccessChallenges:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_challenges;
		break;

	case MIB_KEY_AuthServTotalMalformedAccessRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_bad_req;
		break;

	case MIB_KEY_AuthServTotalBadAuthenticators:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_bad_auth;
		break;
		
	case MIB_KEY_AuthServTotalPacketsDropped:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_dropped;
		break;

	case MIB_KEY_AuthServTotalUnknownTypes:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->auth.num_unknowntypes;
		break;
		
	default:
		*errp = SNMP_ERR_NOSUCHNAME;
		snmp_var_free(ret);
		return NULL;
	}
	return ret;
}

int
snmp_acct_var_set(subid, vp, errp)
	subid_t subid;
	struct snmp_var **vp;
	int *errp;
{
	if (errp) { /* just test */
		*errp = SNMP_ERR_NOERROR;
		switch (subid) {
		
		case MIB_KEY_AuthServConfigReset:
			if ((*vp)->type != ASN_INTEGER ||
			    (*vp)->var_int != serv_reset) {
				*errp = SNMP_ERR_BADVALUE;
				*vp = NULL;
			}
			break;
		default:
			*errp = SNMP_ERR_BADVALUE;
			(*vp) = NULL;
		}
	} else {
		/* do set it */
		*vp = snmp_var_dup(*vp);
		
		switch (subid) {

		case MIB_KEY_AuthServConfigReset:
			server_stat->auth.status = serv_init;
			radlog(L_INFO,
			     _("auth server re-initializing on SNMP request"));
			break;

		}
	}
	return (*vp == NULL);
}

/* Variable oids */

void get_auth_nasstat(NAS *nas, struct snmp_var *var, int ind);
int snmp_auth_v_handler(enum var_subid_cmd cmd, void *closure,
			subid_t subid, struct snmp_var **varp,
			int *errp);
struct snmp_var *snmp_auth_var_v_get(subid_t subid, struct snmp_var *var,
				     int *errp);
void snmp_auth_var_next(struct snmp_var **varp, int *errp);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_auth_v_handler(cmd, closure, subid, varp, errp)
	enum var_subid_cmd cmd;
	void *closure;
	subid_t subid;
	struct snmp_var **varp;
	int *errp;
{
	NAS *nas;
	
	switch (cmd) {
	case VAR_SUBID_GET:
		if ((*varp = snmp_auth_var_v_get(subid, *varp, errp)) == NULL)
			return -1;
		break;
		
	case VAR_SUBID_SET:
	case VAR_SUBID_SET_TRY:
		/* None of these can be set */
		if (errp)
			*errp = SNMP_ERR_NOSUCHNAME;
		return -1;
		
	case VAR_SUBID_COMPARE: 
		return 0;
		
	case VAR_SUBID_NEXT:
		snmp_auth_var_next(varp, errp);
		break;
		
	case VAR_SUBID_RESET:

	}
	
	return 0;
}

void
snmp_auth_var_next(varp, errp)
	struct snmp_var **varp;
	int *errp;
{
	struct snmp_var *ans;
	subid_t subid = SUBID((*varp)->name, OIDLEN((*varp)->name)-1)+1;

	if (!findnasbyindex(subid)) {
		*errp = SNMP_ERR_NOSUCHNAME;
		return;
	}

	if (!(ans = snmp_var_create((*varp)->name))) {
		*errp = SNMP_ERR_GENERR;
		return;
	}

	SUBID(ans->name, OIDLEN(ans->name)-1) = subid;
	
}

struct snmp_var *
snmp_auth_var_v_get(subid, var, errp)
	subid_t subid;
	struct snmp_var *var;
	int *errp;
{
	struct snmp_var *ret;
	struct timeval tv;
	struct timezone tz;
	char *p;
	subid_t key;
	NAS *nas;
	
	ret = snmp_var_create(var->name);
	*errp = SNMP_ERR_NOERROR;

	switch (key = SUBID(var->name, OIDLEN(var->name)-2)) {
	case MIB_KEY_AuthClientIndex:
	case MIB_KEY_AuthClientAddress:
	case MIB_KEY_AuthClientID:
	case MIB_KEY_AuthServAccessRequests:
	case MIB_KEY_AuthServDupAccessRequests:
	case MIB_KEY_AuthServAccessAccepts:
	case MIB_KEY_AuthServAccessRejects:
	case MIB_KEY_AuthServAccessChallenges:
	case MIB_KEY_AuthServMalformedAccessRequests:
	case MIB_KEY_AuthServBadAuthenticators:
	case MIB_KEY_AuthServPacketsDropped:
	case MIB_KEY_AuthServUnknownTypes:
		if ((nas = findnasbyindex(subid)) != NULL &&
		    nas->nas_stat) {
 			get_auth_nasstat(nas, ret, key);
			break;
		}
		/*FALLTHRU*/
	default:
		*errp = SNMP_ERR_NOSUCHNAME;
		snmp_var_free(ret);
		return NULL;
	}
	return ret;
}

void
get_auth_nasstat(nas, var, key)
	NAS *nas;
	struct snmp_var *var;
	int key;
{
	switch (key) {
	case MIB_KEY_AuthClientIndex:
		var->type = ASN_INTEGER;
		var->val_length = sizeof(int);
		var->var_int = nas->nas_stat->index;
		break;
		
	case MIB_KEY_AuthClientAddress:
		var->type = SMI_IPADDRESS;
		var->val_length = sizeof(UINT4);
		var->var_str = snmp_alloc(sizeof(UINT4));
		*(UINT4*)var->var_str = ntohl(nas->nas_stat->ipaddr);
		break;

	case MIB_KEY_AuthClientID:
		var->type = ASN_OCTET_STR;
		var->val_length = strlen(nas->longname);
		var->var_str = snmp_strdup(nas->longname);
		break;

	case MIB_KEY_AuthServAccessRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_access_req;
		break;

	case MIB_KEY_AuthServDupAccessRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_dup_req;
		break;

	case MIB_KEY_AuthServAccessAccepts:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_accepts;
		break;

	case MIB_KEY_AuthServAccessRejects:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_rejects;
		break;

	case MIB_KEY_AuthServAccessChallenges:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_challenges;
		break;

	case MIB_KEY_AuthServMalformedAccessRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_bad_req;
		break;

	case MIB_KEY_AuthServBadAuthenticators:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_bad_auth;
		break;

	case MIB_KEY_AuthServPacketsDropped:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_dropped;
		break;

	case MIB_KEY_AuthServUnknownTypes:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->auth.num_unknowntypes;
		break;
		
	}
}


/* ************************************************************************* */
/* Accounting sub-tree */
struct snmp_var *snmp_acct_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_acct_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */
int
snmp_acct_handler(cmd, closure, subid, varp, errp)
	enum var_subid_cmd cmd;
	void *closure;
	subid_t subid;
	struct snmp_var **varp;
	int *errp;
{
	oid_t oid = (*varp)->name;
	
	switch (cmd) {
	case VAR_SUBID_GET:
		if ((*varp = snmp_acct_var_get(subid, oid, errp)) == NULL)
			return -1;
		break;
		
	case VAR_SUBID_SET:
		return snmp_acct_var_set(subid, varp, errp);
		
	case VAR_SUBID_SET_TRY:
		return snmp_acct_var_set(subid, varp, errp);
		
	case VAR_SUBID_RESET:
		break;
		
	default: /* unused: should never get there */
		abort();

	}
	
	return 0;
}

struct snmp_var *
snmp_acct_var_get(subid, oid, errp)
	subid_t subid;
	oid_t oid;
	int *errp;
{
	struct snmp_var *ret;
	struct timeval tv;
	struct timezone tz;
	char *p;
	
	ret = snmp_var_create(oid);
	*errp = SNMP_ERR_NOERROR;

	switch (subid) {

	case MIB_KEY_AccServIdent:
		p = make_server_ident();
		ret->type = ASN_OCTET_STR;
		ret->val_length = strlen(p);
		ret->var_str = snmp_strdup(p);
		efree(p);
		break;

	case MIB_KEY_AccServUpTime:
		gettimeofday(&tv, &tz);
		ret->type = SMI_TIMETICKS;
		ret->val_length = sizeof(counter);
		ret->var_int = timeval_diff(&tv, &server_stat->start_time);
		break;
		
	case MIB_KEY_AccServResetTime:
		gettimeofday(&tv, &tz);
		ret->type = SMI_TIMETICKS;
		ret->val_length = sizeof(counter);
		ret->var_int = timeval_diff(&tv, &server_stat->acct.reset_time);
		break;

	case MIB_KEY_AccServConfigReset:
		ret->type = ASN_INTEGER;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.status;
		break;
		
	case MIB_KEY_AccServTotalRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_req;
		break;
		
	case MIB_KEY_AccServTotalInvalidRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_invalid_req;
		break;
		
	case MIB_KEY_AccServTotalDupRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_dup_req;
		break;
		
	case MIB_KEY_AccServTotalResponses:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_resp;
		break;
		
	case MIB_KEY_AccServTotalMalformedRequests:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_bad_req;
		break;
		
	case MIB_KEY_AccServTotalBadAuthenticators:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_bad_sign;
		break;
		
	case MIB_KEY_AccServTotalPacketsDropped:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_dropped;
		break;
		
	case MIB_KEY_AccServTotalNoRecords:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_norecords;
		break;
		
	case MIB_KEY_AccServTotalUnknownTypes:
		ret->type = SMI_COUNTER32;
		ret->val_length = sizeof(counter);
		ret->var_int = server_stat->acct.num_unknowntypes;
		break;
		
	default:
		*errp = SNMP_ERR_NOSUCHNAME;
		snmp_var_free(ret);
		return NULL;
	}
	return ret;
}

int
snmp_auth_var_set(subid, vp, errp)
	subid_t subid;
	struct snmp_var **vp;
	int *errp;
{
	if (errp) { /* just test */
		*errp = SNMP_ERR_NOERROR;
		switch (subid) {
		
		case MIB_KEY_AccServConfigReset:
			if ((*vp)->type != ASN_INTEGER ||
			    (*vp)->var_int != serv_reset) {
				*errp = SNMP_ERR_BADVALUE;
				*vp = NULL;
			}
			break;
		default:
			*errp = SNMP_ERR_BADVALUE;
			(*vp) = NULL;
		}
	} else {
		/* do set it */
		*vp = snmp_var_dup(*vp);
		
		switch (subid) {
			
		case MIB_KEY_AccServConfigReset:
			server_stat->acct.status = serv_init;
			radlog(L_INFO,
			     _("acct server re-initializing on SNMP request"));
			break;

		}
	}
	return (*vp == NULL);
}

void get_acct_nasstat(NAS *nas, struct snmp_var *var, int key);
int snmp_acct_v_handler(enum var_subid_cmd cmd, void *closure,
			subid_t subid, struct snmp_var **varp,
			int *errp);
struct snmp_var *snmp_acct_var_v_get(subid_t subid, struct snmp_var *var,
				     int *errp);
void snmp_acct_var_next(struct snmp_var **varp, int *errp);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_acct_v_handler(cmd, closure, subid, varp, errp)
	enum var_subid_cmd cmd;
	void *closure;
	subid_t subid;
	struct snmp_var **varp;
	int *errp;
{
	NAS *nas;
	
	switch (cmd) {
	case VAR_SUBID_GET:
		if ((*varp = snmp_acct_var_v_get(subid, *varp, errp)) == NULL)
			return -1;
		break;
		
	case VAR_SUBID_SET:
	case VAR_SUBID_SET_TRY:
		/* None of these can be set */
		if (errp)
			*errp = SNMP_ERR_NOSUCHNAME;
		return -1;
		
	case VAR_SUBID_COMPARE: 
		return 0;
		
	case VAR_SUBID_NEXT:
		snmp_acct_var_next(varp, errp);
		break;
		
	case VAR_SUBID_RESET:

	}
	
	return 0;
}

/*FIXME: is the same as snmp_auth_var_next */
void
snmp_acct_var_next(varp, errp)
	struct snmp_var **varp;
	int *errp;
{
	struct snmp_var *ans;
	subid_t subid = SUBID((*varp)->name, OIDLEN((*varp)->name)-1)+1;

	if (!findnasbyindex(subid)) {
		*errp = SNMP_ERR_NOSUCHNAME;
		return;
	}

	if (!(ans = snmp_var_create((*varp)->name))) {
		*errp = SNMP_ERR_GENERR;
		return;
	}

	SUBID(ans->name, OIDLEN(ans->name)-1) = subid;
	
}

struct snmp_var *
snmp_acct_var_v_get(subid, var, errp)
	subid_t subid;
	struct snmp_var *var;
	int *errp;
{
	struct snmp_var *ret;
	struct timeval tv;
	struct timezone tz;
	char *p;
	subid_t key;
	NAS *nas;
	
	ret = snmp_var_create(var->name);
	*errp = SNMP_ERR_NOERROR;

	switch (key = SUBID(var->name, OIDLEN(var->name)-2)) {
	case MIB_KEY_AccClientIndex:
	case MIB_KEY_AccClientAddress:
	case MIB_KEY_AccClientID:
	case MIB_KEY_AccServPacketsDropped:
	case MIB_KEY_AccServRequests:
	case MIB_KEY_AccServDupRequests:
	case MIB_KEY_AccServResponses:
	case MIB_KEY_AccServBadAuthenticators:
	case MIB_KEY_AccServMalformedRequests:
	case MIB_KEY_AccServNoRecords:
	case MIB_KEY_AccServUnknownTypes:         
		if ((nas = findnasbyindex(subid)) != NULL &&
		     nas->nas_stat) {
 			get_acct_nasstat(nas, ret, key);
			break;
		}
		/*FALLTHRU*/
	default:
		*errp = SNMP_ERR_NOSUCHNAME;
		snmp_var_free(ret);
		return NULL;
	}
	return ret;
}

void
get_acct_nasstat(nas, var, key)
	NAS *nas;
	struct snmp_var *var;
	int key;
{
	switch (key) {
	case MIB_KEY_AccClientIndex:
		var->type = ASN_INTEGER;
		var->val_length = sizeof(int);
		var->var_int = nas->nas_stat->index;
		break;

	case MIB_KEY_AccClientAddress:
		var->type = SMI_IPADDRESS;
		var->val_length = sizeof(UINT4);
		var->var_str = snmp_alloc(sizeof(UINT4));
		*(UINT4*)var->var_str = ntohl(nas->nas_stat->ipaddr);
		break;

	case MIB_KEY_AccClientID:
		var->type = ASN_OCTET_STR;
		var->val_length = strlen(nas->longname);
		var->var_str = snmp_strdup(nas->longname);
		break;

	case MIB_KEY_AccServPacketsDropped:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_dropped;
		break;

	case MIB_KEY_AccServRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_req;
		break;

	case MIB_KEY_AccServDupRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_dup_req;
		break;

	case MIB_KEY_AccServResponses:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_resp;
		break;

	case MIB_KEY_AccServBadAuthenticators:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_bad_sign;
		break;

	case MIB_KEY_AccServMalformedRequests:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_bad_req;
		break;

	case MIB_KEY_AccServNoRecords:
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_norecords;
		break;

	case MIB_KEY_AccServUnknownTypes:         
		var->type = SMI_COUNTER32;
		var->val_length = sizeof(counter);
		var->var_int = nas->nas_stat->acct.num_unknowntypes;
		break;
	}
}
#endif





