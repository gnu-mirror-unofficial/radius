/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
  
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

#define RADIUS_MODULE_SNMPSERV_C
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#ifdef USE_SNMP

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

#include <sys/types.h>
#include <sys/socket.h>
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

static NAS *nas_lookup_index(int ind);


ACL *snmp_acl, *snmp_acl_tail;
Community *commlist, *commlist_tail;
Server_stat server_stat;
struct radstat radstat;

/* ************************************************************************ */
/* Configuration file */

typedef struct netlist Netlist;
struct netlist {
        Netlist *next;
        char *name;
        ACL *acl;
};
static Netlist *netlist;

static ACL *
find_netlist(name)
        char *name;
{
        Netlist *p;

        for (p = netlist; p; p = p->next)
                if (strcmp(p->name, name) == 0) 
                        return p->acl;

        return NULL;
}

int
snmp_stmt_begin(finish, data, up_data)
	int finish;
	void *data;
	void *up_data;
{
	if (!finish) {
		snmp_free_communities();
		snmp_free_acl();
	}
	return 0;
}

static int
snmp_cfg_ident(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	if (server_id)
		efree(server_id);
	server_id = estrdup(argv[1].v.string);
	return 0;
}

static struct keyword snmp_access[] = {
	"read-only", SNMP_RO,
	"read-write", SNMP_RW,
	"ro", SNMP_RO,
	"rw", SNMP_RW,
	0
};

static int
snmp_cfg_community(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	int access;

	if (argc != 3) {
		cfg_argc_error(argc < 3);
		return 0;
	}

 	if (argv[1].type != CFG_STRING
	    || argv[2].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	access = xlat_keyword(snmp_access, argv[2].v.string, -1);
	if (access == -1) 
		return 1;
		
	if (snmp_find_community(argv[1].v.string)) {
		radlog(L_ERR,
		       _("%s:%d: community %s already declared"),
		       cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}
	
	snmp_add_community(argv[1].v.string, access);
	return 0;
}

static void
destroy_netlist(netlist)
	Netlist *netlist;
{
	free_acl(netlist->acl);
	efree(netlist->name);
}

static int
snmp_cfg_network(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	int i;
	Netlist *p;
	ACL *head = NULL, *tail = NULL;
	
	if (argc < 3) {
		cfg_argc_error(1);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

        p = cfg_malloc(sizeof(*p), destroy_netlist);
        p->next = netlist;
        p->name = estrdup(argv[1].v.string);
	
	for (i = 2; i < argc; i++) {
		if (argv[i].type != CFG_NETWORK) {
			radlog(L_ERR,
			       _("%s:%d: list item %d has wrong datatype"),
			       cfg_filename, cfg_line_num,
			       i);
		} else {
			ACL *acl = alloc_entry(sizeof(*acl));
			acl->ipaddr = argv[i].v.network.ipaddr;
			acl->netmask = argv[i].v.network.netmask;
			if (tail)
				tail->next = acl;
			else
				head = acl;
			tail = acl;
		}
	}
        p->acl = head;
        netlist = p;
	return 0;
}

static int
snmp_cfg_allow(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	Community *comm;
	ACL *acl;
	
	if (argc != 3) {
		cfg_argc_error(argc < 3);
		return 0;
	}
	
 	if (argv[1].type != CFG_STRING || argv[2].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	if ((acl = find_netlist(argv[1].v.string)) == NULL) {
		radlog(L_ERR, _("%s:%d: no such acl: %s"),
		       cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}

	comm = snmp_find_community(argv[2].v.string);
	if (!comm) {
		radlog(L_ERR, 
		       _("%s:%d: undefined community %s"),
		       cfg_filename, cfg_line_num, argv[2].v.string);
		return 0;
	} 

	snmp_add_acl(acl, comm);
	return 0;
}

static int
snmp_cfg_deny(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	ACL *acl;
	
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
	
 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	if ((acl = find_netlist(argv[1].v.string)) == NULL) {
		radlog(L_ERR, _("%s:%d: no such acl: %s"),
		       cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}

	snmp_add_acl(acl, NULL);
	return 0;
}

static struct cfg_stmt acl_stmt[] = {
	{ "allow", CS_STMT, NULL, snmp_cfg_allow, NULL, NULL, NULL },
	{ "deny", CS_STMT, NULL, snmp_cfg_deny, NULL, NULL, NULL },
	{ NULL },
};

struct cfg_stmt snmp_stmt[] = {
	{ "port", CS_STMT, NULL, cfg_get_port, &snmp_port, NULL, NULL },
	{ "max-requests", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_SNMP].max_requests,
	  NULL, NULL },
	{ "time-to-live", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_SNMP].ttl,
	  NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_SNMP].cleanup_delay,
	  NULL, NULL },
	{ "ident", CS_STMT, NULL, snmp_cfg_ident, NULL,
	  NULL, NULL },
	{ "community", CS_STMT, NULL, snmp_cfg_community, NULL, 
	  NULL, NULL },
	{ "network", CS_STMT, NULL, snmp_cfg_network, NULL,
	  NULL, NULL },
	{ "acl", CS_BLOCK, NULL, NULL, NULL, acl_stmt, NULL },
	{ NULL, }
};

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
		new_acl->ipaddr = ntohl(new_acl->ipaddr);
		new_acl->netmask = ntohl(new_acl->netmask);
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
int snmp_auth_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                      struct snmp_var **varp, int *errp);
int snmp_auth_v_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                        struct snmp_var **varp, int *errp);
int snmp_acct_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                      struct snmp_var **varp, int *errp);
int snmp_acct_v_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                        struct snmp_var **varp, int *errp);
int snmp_serv_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                      struct snmp_var **varp, int *errp);
int snmp_serv_queue_handler(enum mib_node_cmd cmd, void *closure,
                            subid_t subid, struct snmp_var **varp, int *errp);
#ifdef SNMP_COMPAT_0_96
int snmp_serv_queue_handler_compat(enum mib_node_cmd cmd, void *closure,
                                   subid_t subid, struct snmp_var **varp,
                                   int *errp);
#endif
int snmp_serv_mem_summary(enum mib_node_cmd cmd, void *closure,
                            subid_t subid, struct snmp_var **varp, int *errp);
int snmp_serv_class_handler(enum mib_node_cmd cmd, void *closure,
                            subid_t subid, struct snmp_var **varp, int *errp);

int snmp_stat_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
                      struct snmp_var **varp, int *errp);

int snmp_stat_nas1(enum mib_node_cmd cmd, void *closure, subid_t subid,
                   struct snmp_var **varp, int *errp);
int snmp_stat_nas2(enum mib_node_cmd cmd, void *closure, subid_t subid,
                   struct snmp_var **varp, int *errp);
int snmp_stat_nas3(enum mib_node_cmd cmd, void *closure, subid_t subid,
                   struct snmp_var **varp, int *errp);
int snmp_stat_nas4(enum mib_node_cmd cmd, void *closure, subid_t subid,
                   struct snmp_var **varp, int *errp);
int snmp_nas_table(enum mib_node_cmd cmd, void *closure, subid_t subid,
                   struct snmp_var **varp, int *errp);
int snmp_port_index1(enum mib_node_cmd cmd, void *closure, subid_t subid,
                     struct snmp_var **varp, int *errp);
int snmp_port_index2(enum mib_node_cmd cmd, void *closure, subid_t subid,
                     struct snmp_var **varp, int *errp);
int snmp_port_table(enum mib_node_cmd cmd, void *closure, subid_t subid,
                    struct snmp_var **varp, int *errp);

struct auth_mib_data {
        int nas_index;
};

struct nas_data {
        subid_t quad[4];
};

struct nas_table_data {
        int row;
};

struct port_data {
        int nas_index;
        int port_no;
};

struct port_table_data {
        int port_index;
};

struct queue_data {
        int queue_index;
};

struct mem_data {
        int mem_index;
};

union snmpserv_data {
        struct auth_mib_data auth_mib;
        struct nas_data nas;
        struct nas_table_data nas_data;
        struct port_data port;
        struct port_table_data port_table;
        struct queue_data queue;
        struct mem_data mem;
};

static pthread_once_t snmpserv_once = PTHREAD_ONCE_INIT;
static pthread_key_t snmpserv_key;

static void
snmpserv_data_destroy(ptr)
        void *ptr;
{
        efree(ptr);
}

static void
snmpserv_data_create()
{
        pthread_key_create(&snmpserv_key, snmpserv_data_destroy);
}

static void *
snmpserv_get_data()
{
        union snmpserv_data *p;
        pthread_once(&snmpserv_once, snmpserv_data_create);
        p = pthread_getspecific(snmpserv_key);
        if (!p) {
                p = emalloc(sizeof(*p));
                p->auth_mib.nas_index = 1;
                pthread_setspecific(snmpserv_key, p);
        }
        return p;
}

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
        oid_AuthClientIndex,                 snmp_auth_v_handler,NULL,
        oid_AuthClientAddress,               snmp_auth_v_handler,NULL,
        oid_AuthClientID,                    snmp_auth_v_handler,NULL,
        oid_AuthServAccessRequests,          snmp_auth_v_handler,NULL,
        oid_AuthServDupAccessRequests,       snmp_auth_v_handler,NULL,
        oid_AuthServAccessAccepts,           snmp_auth_v_handler,NULL,
        oid_AuthServAccessRejects,           snmp_auth_v_handler,NULL,
        oid_AuthServAccessChallenges,        snmp_auth_v_handler,NULL,
        oid_AuthServMalformedAccessRequests, snmp_auth_v_handler,NULL,
        oid_AuthServBadAuthenticators,       snmp_auth_v_handler,NULL,
        oid_AuthServPacketsDropped,          snmp_auth_v_handler,NULL,
        oid_AuthServUnknownTypes,            snmp_auth_v_handler,NULL,
        
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
        oid_AccClientIndex,                  snmp_acct_v_handler,NULL,
        oid_AccClientAddress,                snmp_acct_v_handler,NULL,
        oid_AccClientID,                     snmp_acct_v_handler,NULL,
        oid_AccServPacketsDropped,           snmp_acct_v_handler,NULL,
        oid_AccServRequests,                 snmp_acct_v_handler,NULL,
        oid_AccServDupRequests,              snmp_acct_v_handler,NULL,
        oid_AccServResponses,                snmp_acct_v_handler,NULL,
        oid_AccServBadAuthenticators,        snmp_acct_v_handler,NULL,
        oid_AccServMalformedRequests,        snmp_acct_v_handler,NULL,
        oid_AccServNoRecords,                snmp_acct_v_handler,NULL,
        oid_AccServUnknownTypes,             snmp_acct_v_handler,NULL,

#ifdef SNMP_COMPAT_0_96
        
        /* Server */
        oid_grad_radiusServerUpTime,         snmp_serv_handler, NULL,
        oid_grad_radiusServerResetTime,      snmp_serv_handler, NULL,
        oid_grad_radiusServerState,          snmp_serv_handler, NULL,

        /* Variable oids */
        oid_grad_queueIndex,   snmp_serv_queue_handler_compat, NULL,
        oid_grad_queueName,    snmp_serv_queue_handler_compat, NULL,
        oid_grad_queueActive,  snmp_serv_queue_handler_compat, NULL,
        oid_grad_queueHeld,    snmp_serv_queue_handler_compat, NULL,
        oid_grad_queueTotal,   snmp_serv_queue_handler_compat, NULL,

        oid_grad_memoryNumClasses,      snmp_serv_mem_summary,   NULL,
        oid_grad_memoryNumBuckets,      snmp_serv_mem_summary,   NULL,
        oid_grad_memoryBytesAllocated,  snmp_serv_mem_summary,   NULL,
        oid_grad_memoryBytesUsed,       snmp_serv_mem_summary,   NULL,
        
        oid_grad_classIndex,            snmp_serv_class_handler, NULL,
        oid_grad_classSize,             snmp_serv_class_handler, NULL,
        oid_grad_classElsPerBucket,     snmp_serv_class_handler, NULL,
        oid_grad_classNumBuckets,       snmp_serv_class_handler, NULL,
        oid_grad_classElsUsed,          snmp_serv_class_handler, NULL,
        
        oid_grad_memoryMallocBlocks,    snmp_serv_mem_summary,   NULL,
        oid_grad_memoryMallocBytes,     snmp_serv_mem_summary,   NULL,
        
        /* Statistics */
        oid_grad_StatIdent,             snmp_stat_handler, NULL,
        oid_grad_StatUpTime,            snmp_stat_handler, NULL,
        oid_grad_StatConfigReset,       snmp_stat_handler, NULL,
        oid_grad_StatTotalLines,        snmp_stat_handler, NULL,
        oid_grad_StatTotalLinesInUse,   snmp_stat_handler, NULL,
        oid_grad_StatTotalLinesIdle,    snmp_stat_handler, NULL,

        /* Variable oids */
        oid_grad_NASIndex1,             snmp_stat_nas1, NULL,
        oid_grad_NASIndex2,             snmp_stat_nas2, NULL,
        oid_grad_NASIndex3,             snmp_stat_nas3, NULL,
        oid_grad_NASIndex4,             snmp_stat_nas4, NULL,

        oid_grad_NASAddress,            snmp_nas_table, NULL,
        oid_grad_NASID,                 snmp_nas_table, NULL,
        oid_grad_NASLines,              snmp_nas_table, NULL,
        oid_grad_NASLinesInUse,         snmp_nas_table, NULL,
        oid_grad_NASLinesIdle,          snmp_nas_table, NULL,

        oid_grad_StatPortIndex1,        snmp_port_index1, NULL,
        oid_grad_StatPortIndex2,        snmp_port_index2, NULL,

        /* port table */
        oid_grad_StatPortNASIndex,      snmp_port_table, NULL,
        oid_grad_StatPortID,            snmp_port_table, NULL,
        oid_grad_StatPortFramedAddress, snmp_port_table, NULL,
        oid_grad_StatPortTotalLogins,   snmp_port_table, NULL,
        oid_grad_StatPortStatus,        snmp_port_table, NULL,
        oid_grad_StatPortStatusChangeTimestamp,   snmp_port_table, NULL,
        oid_grad_StatPortUpTime,        snmp_port_table, NULL,
        oid_grad_StatPortLastLoginName, snmp_port_table, NULL,
        oid_grad_StatPortLastLoginTimestamp,  snmp_port_table, NULL,
        oid_grad_StatPortLastLogoutTimestamp, snmp_port_table, NULL,
        oid_grad_StatPortIdleTotalTime, snmp_port_table, NULL,
        oid_grad_StatPortIdleMaxTime,   snmp_port_table, NULL,
        oid_grad_StatPortIdleMaxTimestamp, snmp_port_table, NULL,
        oid_grad_StatPortInUseTotalTime, snmp_port_table, NULL,
        oid_grad_StatPortInUseMaxTime,   snmp_port_table, NULL,
        oid_grad_StatPortInUseMaxTimestamp, snmp_port_table, NULL,
#endif
        /* enterprise.gnu.radius subtree */
        /* Server */
        oid_radiusServerUpTime,         snmp_serv_handler, NULL,
        oid_radiusServerResetTime,      snmp_serv_handler, NULL,
        oid_radiusServerState,          snmp_serv_handler, NULL,

        /* Variable oids */
        oid_queueIndex,     snmp_serv_queue_handler, NULL,
        oid_queueName,      snmp_serv_queue_handler, NULL,
        oid_queueWaiting,   snmp_serv_queue_handler, NULL,
        oid_queuePending,   snmp_serv_queue_handler, NULL,
        oid_queueCompleted, snmp_serv_queue_handler, NULL,
        oid_queueTotal,     snmp_serv_queue_handler, NULL,

        oid_memoryNumClasses,      snmp_serv_mem_summary,   NULL,
        oid_memoryNumBuckets,      snmp_serv_mem_summary,   NULL,
        oid_memoryBytesAllocated,  snmp_serv_mem_summary,   NULL,
        oid_memoryBytesUsed,       snmp_serv_mem_summary,   NULL,
        
        oid_classIndex,         snmp_serv_class_handler, NULL,
        oid_classSize,          snmp_serv_class_handler, NULL,
        oid_classElsPerBucket,     snmp_serv_class_handler, NULL,
        oid_classNumBuckets,    snmp_serv_class_handler, NULL,
        oid_classElsUsed,          snmp_serv_class_handler, NULL,
        
        oid_memoryMallocBlocks, snmp_serv_mem_summary,   NULL,
        oid_memoryMallocBytes,  snmp_serv_mem_summary,   NULL,

        /* Statistics */
        oid_StatIdent,                       snmp_stat_handler, NULL,
        oid_StatUpTime,                      snmp_stat_handler, NULL,
        oid_StatConfigReset,                 snmp_stat_handler, NULL,
        oid_StatTotalLines,                  snmp_stat_handler, NULL,
        oid_StatTotalLinesInUse,             snmp_stat_handler, NULL,
        oid_StatTotalLinesIdle,              snmp_stat_handler, NULL,

        /* Variable oids */
        oid_NASIndex1,                       snmp_stat_nas1, NULL,
        oid_NASIndex2,                       snmp_stat_nas2, NULL,
        oid_NASIndex3,                       snmp_stat_nas3, NULL,
        oid_NASIndex4,                       snmp_stat_nas4, NULL,

        oid_NASAddress,                      snmp_nas_table, NULL,
        oid_NASID,                           snmp_nas_table, NULL,
        oid_NASLines,                        snmp_nas_table, NULL,
        oid_NASLinesInUse,                   snmp_nas_table, NULL,
        oid_NASLinesIdle,                    snmp_nas_table, NULL,

        oid_StatPortIndex1,                  snmp_port_index1, NULL,
        oid_StatPortIndex2,                  snmp_port_index2, NULL,

        /* port table */
        oid_StatPortNASIndex,                snmp_port_table, NULL,
        oid_StatPortID,                      snmp_port_table, NULL,
        oid_StatPortFramedAddress,           snmp_port_table, NULL,
        oid_StatPortTotalLogins,             snmp_port_table, NULL,
        oid_StatPortStatus,                  snmp_port_table, NULL,
        oid_StatPortStatusChangeTimestamp,   snmp_port_table, NULL,
        oid_StatPortUpTime,                  snmp_port_table, NULL,
        oid_StatPortLastLoginName,           snmp_port_table, NULL,
        oid_StatPortLastLoginTimestamp,      snmp_port_table, NULL,
        oid_StatPortLastLogoutTimestamp,     snmp_port_table, NULL,
        oid_StatPortIdleTotalTime,           snmp_port_table, NULL,
        oid_StatPortIdleMaxTime,             snmp_port_table, NULL,
        oid_StatPortIdleMaxTimestamp,        snmp_port_table, NULL,
        oid_StatPortInUseTotalTime,          snmp_port_table, NULL,
        oid_StatPortInUseMaxTime,            snmp_port_table, NULL,
        oid_StatPortInUseMaxTimestamp,       snmp_port_table, NULL,

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

/* Mark reset of the auth server. Do not do any real work, though.
 */
void
snmp_auth_server_reset()
{
        struct timeval tv;
        struct timezone tz;

        gettimeofday(&tv, &tz);
        server_stat.auth.reset_time = tv;
}

/* Mark reset of the acct server. Again, no real work, please.
 */
void
snmp_acct_server_reset()
{
        struct timeval tv;
        struct timezone tz;

        gettimeofday(&tv, &tz);
        server_stat.acct.reset_time = tv;
}

static int              i_send_buffer[1024];
static char             *send_buffer = (char *)i_send_buffer;

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
                ("got %d bytes from %s",
                 len,
                 ip_iptostr(ntohl(req->sa.sin_addr.s_addr), ipbuf)));
        
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
        char comm[128];
        int comm_len;
        char ipbuf[DOTTED_QUAD_LEN];
        
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
                         ip_iptostr(ntohl(req->sa.sin_addr.s_addr), ipbuf),
                         snmp_strerror(snmp_errno));
                return -1;
        }

        access = check_acl(req->sa.sin_addr.s_addr, comm);
        if (!access) {
                radlog(L_NOTICE,
                       _("DENIED attempt to access community %s from %s"),
                       comm,
                       ip_iptostr(ntohl(req->sa.sin_addr.s_addr), ipbuf));
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

/*ARGSUSED*/
void
snmp_req_drop(type, req, orig, fd, status_str)
        int type;
        SNMP_REQ *req;
	SNMP_REQ *orig;
	int fd;
        char *status_str;
{
        char ipbuf[DOTTED_QUAD_LEN];

	if (!req)
		req = orig;
        radlog(L_NOTICE,
               _("Dropping SNMP request from client %s: %s"),
               ip_iptostr(ntohl(req->sa.sin_addr.s_addr), ipbuf),
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

        log_open(L_SNMP);
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

int mib_down(struct mib_node_t *node, oid_t oid);
void mib_reset(struct mib_node_t *node);

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
        for (i = node->index; node && i >= 0; i--, node = node->up) {
                SUBID(oid,i) = (node->subid != SUBID_X) ?
                                 node->subid :
                                 (subid_t)(*node->handler)(MIB_NODE_GET_SUBID,
                                                           node->closure,
                                                           0,
                                                           NULL, NULL);
        }
        return oid;
}

void
mib_reset(node)
        struct mib_node_t *node;
{
        if (node->subid == SUBID_X) {
                (*node->handler)(MIB_NODE_RESET, node->closure,
                                 0,
                                 NULL, NULL);
        }
}
                
int
mib_down(node, oid)
        struct mib_node_t *node;
        oid_t oid;
{
        if (node->subid == SUBID_X) {
                if (OIDLEN(oid) <= node->index) {
                    (*node->handler)(MIB_NODE_RESET, node->closure,
                                     0,
                                     NULL, NULL);
                    return 0;
                } else if ((*node->handler)(MIB_NODE_NEXT, node->closure,
                                            SUBID(oid,node->index),
                                            NULL, NULL) == 0) 
                        return 0;
        }
        return 1;
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
                int depth = 0;
                node = found_node;
                mib_reset(node);
                        
                while (node) {
                        if (depth++ && node->next == NULL) 
                                break;

                        if (node->next) {
                                node = node->next;
                                mib_reset(node);
                        } else if (node->subid == SUBID_X) {
                                if (mib_down(node, oid))
                                        node = NULL;
                        } else
                                node = node->down;
                }
                
                if (!node) {
                        /* The subtree is exhausted. Roll back until we find
                           first non-traversed down link */
                        debug(2, ("rolling back from %d:%d",
                                  found_node->index,
                                  found_node->subid));
                        while (node = found_node->up) {
                                mib_reset(node);
                                if (node->down && node->down != found_node)
                                        break;
                                if (node->subid == SUBID_X &&
                                    mib_down(node, oid) == 0) 
                                        break;
                                found_node = node;
                        }

                        if (node)
                                debug(2, ("rollback stopped at %d:%d",
                                          node->index,
                                          node->subid));

                        if (node && node->subid != SUBID_X)
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
        (*found_node->handler)(MIB_NODE_GET,
                               found_node->closure,
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
        oid_t oid = (*varp)->name;
        
        if (mib_lookup(node, oid, OIDLEN(oid), &node) != MIB_MATCH_EXACT ||
            !node->handler) {
                *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
        }

        return (*node->handler)(MIB_NODE_GET, node->closure,
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
        oid_t oid = (*varp)->name;
        
        if (mib_lookup(node, oid, OIDLEN(oid), &node) != MIB_MATCH_EXACT ||
            !node->handler) {
                *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
        }
        
        if ((*node->handler)(MIB_NODE_SET_TRY, node->closure,
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
        oid_t oid = (*varp)->name;
        
        if (mib_lookup(node, oid, OIDLEN(oid), &node) != MIB_MATCH_EXACT ||
            !node->handler) {
                return -1;
        }
        
        return (*node->handler)(MIB_NODE_SET, node->closure,
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
                        for (vpp = &pdu->var; *vpp; vpp = &(*vpp)->next) {
                                vp = *vpp;

                                index++;

                                vnew = vp;
                                mib_get(mib_tree, &vnew,
                                        &answer->err_stat);
                                
                                /* Was there an error? */
                                if (answer->err_stat != SNMP_ERR_NOERROR
                                    || vnew == NULL) {
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

                        vresp = &answer->var;
                        /* Loop through all variables */
                        for (vpp = &pdu->var; *vpp; vpp = &(*vpp)->next) {
                                vp = *vpp;

                                index++;
                                vnew = vp;
                                mib_get_next(mib_tree, &vnew,
                                             &answer->err_stat);
                                /* Was there an error? */
                                if (answer->err_stat != SNMP_ERR_NOERROR
                                    || vnew == NULL) {
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

serv_stat
abridge_server_state()
{
        switch (server_stat.auth.status) {
        case serv_init:
        case serv_running:
                return server_stat.auth.status;
        case serv_other:
        default:
                return serv_other;
        }
}

/* ************************************************************************* */
/* Auth sub-tree */

struct snmp_var *snmp_auth_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_auth_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */
/*ARGSUSED*/
int
snmp_auth_handler(cmd, closure, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        oid_t oid = (*varp)->name;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_auth_var_get(subid, oid, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
                return snmp_auth_var_set(subid, varp, errp);
                
        case MIB_NODE_SET_TRY:
                return snmp_auth_var_set(subid, varp, errp);
                
        case MIB_NODE_RESET:
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
                ret->var_int = timeval_diff(&tv, &server_stat.start_time);
                break;

        case MIB_KEY_AuthServResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(counter);
                ret->var_int = timeval_diff(&tv,
                                            &server_stat.auth.reset_time);
                break;

        case MIB_KEY_AuthServConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(counter);
                ret->var_int = abridge_server_state();
                break;

        case MIB_KEY_AuthServTotalAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_access_req;
                break;

        case MIB_KEY_AuthServTotalInvalidRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_invalid_req;
                break;

        case MIB_KEY_AuthServTotalDupAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_dup_req;
                break;

        case MIB_KEY_AuthServTotalAccessAccepts:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_accepts;
                break;

        case MIB_KEY_AuthServTotalAccessRejects:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_rejects;
                break;

        case MIB_KEY_AuthServTotalAccessChallenges:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_challenges;
                break;

        case MIB_KEY_AuthServTotalMalformedAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_bad_req;
                break;

        case MIB_KEY_AuthServTotalBadAuthenticators:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_bad_auth;
                break;
                
        case MIB_KEY_AuthServTotalPacketsDropped:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_dropped;
                break;

        case MIB_KEY_AuthServTotalUnknownTypes:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.num_unknowntypes;
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
                        server_stat.auth.status = serv_init;
                        radlog(L_INFO,
                             _("acct server re-initializing on SNMP request"));
                        break;

                }
        }
        return (*vp == NULL);
}

/* Variable oids */

void get_auth_nasstat(NAS *nas, struct snmp_var *var, int ind);
int snmp_auth_v_handler(enum mib_node_cmd cmd, void *closure,
                        subid_t subid, struct snmp_var **varp,
                        int *errp);
struct snmp_var *snmp_auth_var_v_get(subid_t subid, struct snmp_var *var,
                                     int *errp);
int snmp_auth_var_next(subid_t subid, struct auth_mib_data *closure);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_auth_v_handler(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct auth_mib_data *data = (struct auth_mib_data *)
                                            snmpserv_get_data();
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_auth_var_v_get(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                return snmp_auth_var_next(subid+1, data);

        case MIB_NODE_GET_SUBID:
                return data->nas_index;
                
        case MIB_NODE_RESET:
                data->nas_index = 1;
                break;
                
        }
        
        return 0;
}

int
snmp_auth_var_next(subid, closure)
        subid_t subid;
        struct auth_mib_data *closure;
{
        if (!nas_lookup_index(subid)) 
                return -1;

        closure->nas_index = subid;
        return 0;
}

struct snmp_var *
snmp_auth_var_v_get(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
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
                if ((nas = nas_lookup_index(subid)) != NULL &&
                    nas->app_data) {
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
        struct nas_stat *statp = nas->app_data;
        
        switch (key) {
        case MIB_KEY_AuthClientIndex:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = statp->index;
                break;
                
        case MIB_KEY_AuthClientAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(UINT4);
                var->var_str = snmp_alloc(sizeof(UINT4));
                *(UINT4*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_AuthClientID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_AuthServAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_access_req;
                break;

        case MIB_KEY_AuthServDupAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_dup_req;
                break;

        case MIB_KEY_AuthServAccessAccepts:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_accepts;
                break;

        case MIB_KEY_AuthServAccessRejects:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_rejects;
                break;

        case MIB_KEY_AuthServAccessChallenges:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_challenges;
                break;

        case MIB_KEY_AuthServMalformedAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_bad_req;
                break;

        case MIB_KEY_AuthServBadAuthenticators:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_bad_auth;
                break;

        case MIB_KEY_AuthServPacketsDropped:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_dropped;
                break;

        case MIB_KEY_AuthServUnknownTypes:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->auth.num_unknowntypes;
                break;
                
        }
}


/* ************************************************************************* */
/* Accounting sub-tree */
struct snmp_var *snmp_acct_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_acct_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */
/*ARGSUSED*/
int
snmp_acct_handler(cmd, closure, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        oid_t oid = (*varp)->name;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_acct_var_get(subid, oid, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
                return snmp_acct_var_set(subid, varp, errp);
                
        case MIB_NODE_SET_TRY:
                return snmp_acct_var_set(subid, varp, errp);
                
        case MIB_NODE_RESET:
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
                ret->var_int = timeval_diff(&tv, &server_stat.start_time);
                break;
                
        case MIB_KEY_AccServResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(counter);
                ret->var_int = timeval_diff(&tv, &server_stat.acct.reset_time);
                break;

        case MIB_KEY_AccServConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(counter);
                ret->var_int = abridge_server_state();
                break;
                
        case MIB_KEY_AccServTotalRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_req;
                break;
                
        case MIB_KEY_AccServTotalInvalidRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_invalid_req;
                break;
                
        case MIB_KEY_AccServTotalDupRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_dup_req;
                break;
                
        case MIB_KEY_AccServTotalResponses:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_resp;
                break;
                
        case MIB_KEY_AccServTotalMalformedRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_bad_req;
                break;
                
        case MIB_KEY_AccServTotalBadAuthenticators:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_bad_sign;
                break;
                
        case MIB_KEY_AccServTotalPacketsDropped:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_dropped;
                break;
                
        case MIB_KEY_AccServTotalNoRecords:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_norecords;
                break;
                
        case MIB_KEY_AccServTotalUnknownTypes:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.acct.num_unknowntypes;
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
                        server_stat.auth.status = serv_init;
                        radlog(L_INFO,
                             _("auth server re-initializing on SNMP request"));
                        break;

                }
        }
        return (*vp == NULL);
}

void get_acct_nasstat(NAS *nas, struct snmp_var *var, int key);
int snmp_acct_v_handler(enum mib_node_cmd cmd, void *closure,
                        subid_t subid, struct snmp_var **varp,
                        int *errp);
struct snmp_var *snmp_acct_var_v_get(subid_t subid, struct snmp_var *var,
                                     int *errp);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_acct_v_handler(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct auth_mib_data *data = (struct auth_mib_data *)
                                        snmpserv_get_data();
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_acct_var_v_get(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                return snmp_auth_var_next(subid+1, data);
                
        case MIB_NODE_GET_SUBID:
                return data->nas_index;
                
        case MIB_NODE_RESET:
                data->nas_index = 1;
                break;

        }
        
        return 0;
}

struct snmp_var *
snmp_acct_var_v_get(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
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
                if ((nas = nas_lookup_index(subid)) != NULL &&
                     nas->app_data) {
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
        struct nas_stat *statp = nas->app_data;
        
        switch (key) {
        case MIB_KEY_AccClientIndex:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = statp->index;
                break;

        case MIB_KEY_AccClientAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(UINT4);
                var->var_str = snmp_alloc(sizeof(UINT4));
                *(UINT4*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_AccClientID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_AccServPacketsDropped:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_dropped;
                break;

        case MIB_KEY_AccServRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_req;
                break;

        case MIB_KEY_AccServDupRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_dup_req;
                break;

        case MIB_KEY_AccServResponses:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_resp;
                break;

        case MIB_KEY_AccServBadAuthenticators:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_bad_sign;
                break;

        case MIB_KEY_AccServMalformedRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_bad_req;
                break;

        case MIB_KEY_AccServNoRecords:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_norecords;
                break;

        case MIB_KEY_AccServUnknownTypes:         
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->acct.num_unknowntypes;
                break;
        }
}

/* ************************************************************************* */
/* Server */
struct snmp_var *snmp_serv_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_serv_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the server subtree */
/*ARGSUSED*/
int
snmp_serv_handler(cmd, closure, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        oid_t oid = (*varp)->name;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_serv_var_get(subid, oid, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
                return snmp_serv_var_set(subid, varp, errp);
                
        case MIB_NODE_SET_TRY:
                return snmp_serv_var_set(subid, varp, errp);
                
        case MIB_NODE_RESET:
                break;
                
        default: /* unused: should never get there */
                abort();

        }
        
        return 0;
}

struct snmp_var *
snmp_serv_var_get(subid, oid, errp)
        subid_t subid;
        oid_t oid;
        int *errp;
{
        struct snmp_var *ret;
        struct timeval tv;
        struct timezone tz;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (subid) {

        case MIB_KEY_radiusServerUpTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(counter);
                ret->var_int = timeval_diff(&tv, &server_stat.start_time);
                break;

        case MIB_KEY_radiusServerResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(counter);
                ret->var_int = timeval_diff(&tv,
                                            &server_stat.auth.reset_time);
                break;

        case MIB_KEY_radiusServerState:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(counter);
                ret->var_int = server_stat.auth.status;/*FIXME*/
                break;
        default:
                *errp = SNMP_ERR_NOSUCHNAME;
                snmp_var_free(ret);
                return NULL;
        }
        return ret;
}

int
snmp_serv_var_set(subid, vp, errp)
        subid_t subid;
        struct snmp_var **vp;
        int *errp;
{
        if (errp) { /* just test */
                *errp = SNMP_ERR_NOERROR;
                switch (subid) {
                
                case MIB_KEY_radiusServerState:
                        if ((*vp)->type != ASN_INTEGER) {
                                *errp = SNMP_ERR_BADVALUE;
                                *vp = NULL;
                        } else {
                                switch ((*vp)->var_int) {
                                case serv_reset:
                                case serv_init:
                                case serv_running:
                                case serv_suspended:
                                case serv_shutdown:
                                        break;
                                default:
                                        *errp = SNMP_ERR_BADVALUE;
                                        *vp = NULL;
                                }
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

                case MIB_KEY_radiusServerState:
                        server_stat.auth.status = (*vp)->var_int;
                        switch ((*vp)->var_int) {
                        case serv_reset:
                                radlog(L_NOTICE,
                                       _("server re-initializing on SNMP request"));
                                break;
                        case serv_init:
                                radlog(L_NOTICE,
                                       _("server restart on SNMP request"));
                                break;
                        case serv_running:
                                radlog(L_NOTICE,
                                       _("server continuing on SNMP request"));
                                break;
                        case serv_suspended:
                                radlog(L_NOTICE,
                                       _("server suspending on SNMP request"));
                                break;
                        case serv_shutdown:
                                radlog(L_NOTICE,
                                       _("server shutting down on SNMP request"));
                                break;
                        }
                        break;

                }
        }
        return (*vp == NULL);
}


/* Variable oids */

#ifdef SNMP_COMPAT_0_96
static struct snmp_var *snmp_queue_get_compat(subid_t subid,
                                              struct snmp_var *var,
                                              int *errp);
static void get_queue_stat_compat(int qno, struct snmp_var *var, subid_t key);

int
snmp_serv_queue_handler_compat(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct queue_data *p = (struct queue_data *) snmpserv_get_data();
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_queue_get_compat(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                if (subid < R_MAX) {
                        p->queue_index = subid+1;
                        return 0;
                }
                return -1;
                
        case MIB_NODE_GET_SUBID:
                return p->queue_index;
                
        case MIB_NODE_RESET:
                p->queue_index = 1;
                break;

        }
        
        return 0;
}

struct snmp_var *
snmp_queue_get_compat(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
        subid_t key;
        oid_t oid = var->name;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (key = SUBID(oid, OIDLEN(oid)-2)) {

        case MIB_KEY_queueIndex:
        case MIB_KEY_queueName:                 
        case MIB_KEY_grad_queueActive:
        case MIB_KEY_grad_queueHeld:
        case MIB_KEY_grad_queueTotal:
                if (subid-1 < R_MAX) {
                        get_queue_stat_compat(subid-1, ret, key);
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
get_queue_stat_compat(qno, var, key)
        int qno;
        struct snmp_var *var;
        subid_t key;
{
        struct timeval tv;
        struct timezone tz;
        QUEUE_STAT stat;
        
        request_stat_list(stat);
        switch (key) {
        case MIB_KEY_queueIndex:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = qno+1;
                break;
                
        case MIB_KEY_queueName:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(request_class[qno].name);
                var->var_str = snmp_strdup(request_class[qno].name);
                break;

        case MIB_KEY_grad_queueActive:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].pending;
                break;
                
        case MIB_KEY_grad_queueHeld:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].waiting + stat[qno].completed;
                break;

        case MIB_KEY_grad_queueTotal:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].pending
                               + stat[qno].waiting
                               + stat[qno].completed;
                break;
        }
}
#endif

/* Queue table */
static struct snmp_var *snmp_queue_get(subid_t subid, struct snmp_var *var,
                                       int *errp);
static void get_queue_stat(int qno, struct snmp_var *var, subid_t key);

int
snmp_serv_queue_handler(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct queue_data *p = (struct queue_data *) snmpserv_get_data();
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_queue_get(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                if (subid < R_MAX) {
                        p->queue_index = subid+1;
                        return 0;
                }
                return -1;
                
        case MIB_NODE_GET_SUBID:
                return p->queue_index;
                
        case MIB_NODE_RESET:
                p->queue_index = 1;
                break;

        }
        
        return 0;
}

struct snmp_var *
snmp_queue_get(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
        subid_t key;
        oid_t oid = var->name;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (key = SUBID(oid, OIDLEN(oid)-2)) {

        case MIB_KEY_queueIndex:
        case MIB_KEY_queueName:                 
        case MIB_KEY_queueWaiting:
        case MIB_KEY_queuePending:
        case MIB_KEY_queueCompleted:
        case MIB_KEY_queueTotal:
                if (subid-1 < R_MAX) {
                        get_queue_stat(subid-1, ret, key);
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
get_queue_stat(qno, var, key)
        int qno;
        struct snmp_var *var;
        subid_t key;
{
        QUEUE_STAT stat;
        
        request_stat_list(stat);
        switch (key) {
        case MIB_KEY_queueIndex:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = qno+1;
                break;
                
        case MIB_KEY_queueName:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(request_class[qno].name);
                var->var_str = snmp_strdup(request_class[qno].name);
                break;

        case MIB_KEY_queuePending:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].pending;
                break;
                
        case MIB_KEY_queueWaiting:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].waiting;
                break;

        case MIB_KEY_queueCompleted:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].completed;
                break;

        case MIB_KEY_queueTotal:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat[qno].pending
                               + stat[qno].waiting
                               + stat[qno].completed;
                break;
        }
}

/* Memory table */
static struct snmp_var *snmp_mem_get(subid_t subid, oid_t oid, int *errp);
static struct snmp_var *snmp_class_get(subid_t subid,
                                       struct snmp_var *varp, int *errp);
static int _mem_get_class(subid_t, CLASS_STAT*);
static void get_class_stat(CLASS_STAT *stat, struct snmp_var *var,
                           subid_t key);

int
snmp_serv_mem_summary(cmd, closure, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        oid_t oid = (*varp)->name;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_mem_get(subid, oid, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_RESET:
                break;

        default:
                abort();

        }
        
        return 0;
}

struct snmp_var *
snmp_mem_get(subid, oid, errp)
        subid_t subid;
        oid_t oid;
        int *errp;
{
        struct snmp_var *ret;
        MEM_STAT stat;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        mem_get_stat(&stat);
        
        switch (subid) {

        case MIB_KEY_memoryNumClasses:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = stat.class_cnt;
                break;
                
        case MIB_KEY_memoryNumBuckets:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = stat.bucket_cnt;
                break;

        case MIB_KEY_memoryBytesAllocated:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = stat.bytes_allocated;
                break;

        case MIB_KEY_memoryBytesUsed:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                ret->var_int = stat.bytes_used;
                break;
                
        case MIB_KEY_memoryMallocBlocks:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
#ifdef LEAK_DETECTOR
                ret->var_int = mallocstat.count;
#else
                ret->var_int = 0;
#endif
                break;
                
        case MIB_KEY_memoryMallocBytes:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
#ifdef LEAK_DETECTOR
                ret->var_int = mallocstat.size;
#else
                ret->var_int = 0;
#endif
                break;
                
        default:
                *errp = SNMP_ERR_NOSUCHNAME;
                snmp_var_free(ret);
                return NULL;
        }
        return ret;
}

static int
class_counter(stat, ret)
        CLASS_STAT *stat;
        CLASS_STAT *ret;
{
        if (stat->index == ret->index) {
                *ret = *stat;
                return 1;
        }
        return 0;
}

int
_mem_get_class(subid, stat)
        subid_t subid;
        CLASS_STAT *stat;
{
        stat->index = subid;
        return mem_stat_enumerate(class_counter, stat);
}

int
snmp_serv_class_handler(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct mem_data *p = (struct mem_data *) snmpserv_get_data();
        CLASS_STAT stat;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_class_get(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                if (_mem_get_class(subid, &stat)) {
                        p->mem_index = subid+1;
                        return 0;
                }
                return -1;
                
        case MIB_NODE_GET_SUBID:
                return p->mem_index;
                
        case MIB_NODE_RESET:
                p->mem_index = 1;
                break;

        }
        
        return 0;
}

struct snmp_var *
snmp_class_get(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
        subid_t key;
        oid_t oid = var->name;
        CLASS_STAT stat;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (key = SUBID(oid, OIDLEN(oid)-2)) {

        case MIB_KEY_classIndex:
        case MIB_KEY_classSize:                 
        case MIB_KEY_classElsPerBucket:
        case MIB_KEY_classNumBuckets:
        case MIB_KEY_classElsUsed:
                if (_mem_get_class(subid-1, &stat)) {
                        get_class_stat(&stat, ret, key);
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
get_class_stat(stat, var, key)
        CLASS_STAT *stat;
        struct snmp_var *var;
        subid_t key;
{
        switch (key) {
        case MIB_KEY_classIndex:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = stat->index+1;
                break;
        case MIB_KEY_classSize:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = stat->elsize;
                break;
        case MIB_KEY_classElsPerBucket:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat->elcnt;
                break;
        case MIB_KEY_classNumBuckets:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat->bucket_cnt;
                break;
        case MIB_KEY_classElsUsed:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = stat->allocated_cnt;
                break;
        }
}

/* ************************************************************************* */
/* Statistics */
struct snmp_var *snmp_stat_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_stat_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */
/*ARGSUSED*/
int
snmp_stat_handler(cmd, closure, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        oid_t oid = (*varp)->name;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_stat_var_get(subid, oid, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /*FIXME: return snmp_stat_var_set(subid, varp, errp); */
                *errp = SNMP_ERR_BADVALUE;
                return -1;
                
        case MIB_NODE_RESET:
                break;
                
        default: /* unused: should never get there */
                abort();

        }
        
        return 0;
}

struct snmp_var *
snmp_stat_var_get(subid, oid, errp)
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

        case MIB_KEY_StatIdent:
                p = make_server_ident();
                ret->type = ASN_OCTET_STR;
                ret->val_length = strlen(p);
                ret->var_str = snmp_strdup(p);
                efree(p);
                break;

        case MIB_KEY_StatUpTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(counter);
                ret->var_int = timeval_diff(&tv, &radstat.start_time);
                break;

        case MIB_KEY_StatConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(counter);
                ret->var_int = serv_running;;
                break;

        case MIB_KEY_StatTotalLines:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                stat_count_ports();
                ret->var_int = radstat.port_active_count
                            + radstat.port_idle_count;
                break;

        case MIB_KEY_StatTotalLinesInUse:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                stat_count_ports();
                ret->var_int = radstat.port_active_count;
                break;

        case MIB_KEY_StatTotalLinesIdle:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(counter);
                stat_count_ports();
                ret->var_int = radstat.port_idle_count;
                break;
                
        default:
                *errp = SNMP_ERR_NOSUCHNAME;
                snmp_var_free(ret);
                return NULL;
        }
        return ret;
}

int
snmp_stat_nas(num, cmd, closure, subid, varp, errp)
        int num;
        enum mib_node_cmd cmd;
        struct nas_data *closure;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        NAS *nas;
        struct nas_stat *nsp;
        UINT4 ip;
        struct snmp_var *var;
        int len;
        
        switch (cmd) {
        case MIB_NODE_GET:
                if (SUBID((*varp)->name, 6) == 9163)
                        len = LEN_grad_NASIndex4;
                else
                        len = LEN_NASIndex4;
                        
                if (num != 3 || OIDLEN((*varp)->name) != len) {
                        *errp = SNMP_ERR_NOSUCHNAME;
                        return -1;
                }
                ip = (closure->quad[0]<<24)+
                        (closure->quad[1]<<16)+
                        (closure->quad[2]<<8) +
                        closure->quad[3];

                if ((nsp = find_nas_stat(ip)) == NULL) {
                        *errp = SNMP_ERR_NOSUCHNAME;
                        return -1;
                }

                *errp = SNMP_ERR_NOERROR;
                var = snmp_var_create((*varp)->name);
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = nsp->index;

                *varp = var;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE:
                closure->quad[num] = subid;
                return 0;
                
        case MIB_NODE_NEXT:
                if (num != 3)
                        return  -1; 

                ip = (closure->quad[0]<<24)+
                        (closure->quad[1]<<16)+
                        (closure->quad[2]<<8) +
                        closure->quad[3];

                if ((nas = nas_lookup_ip(ip)) == NULL) {
                        return -1;
                }
                
                nsp = nas->app_data;
                if ((nas = nas_lookup_index(nsp->index+1)) == NULL) {
                        return -1;
                }

                for (num = 0; num < 4; num++)
                        closure->quad[num] = (nas->ipaddr >>
                                              (8*(3-num))) & 0xff;
                
                break;
                
        case MIB_NODE_GET_SUBID:
                return closure->quad[num];
                
        case MIB_NODE_RESET:
                if (num == 0) {
                        if (nas = nas_lookup_index(1))
                                for (num = 0; num < 4; num++)
                                        closure->quad[num] = (nas->ipaddr >>
                                                              (8*(3-num))) & 0xff;
                }
                break;

        }
        
        return 0;
}

int
snmp_stat_nas1(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        return snmp_stat_nas(0, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas2(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        return snmp_stat_nas(1, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas3(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        return snmp_stat_nas(2, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas4(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        return snmp_stat_nas(3, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}


void get_stat_nasstat(NAS *nas, struct snmp_var *var, int ind);
struct snmp_var *snmp_nas_table_get(subid_t subid, oid_t oid, int *errp);

int
snmp_nas_table(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct nas_table_data *data = (struct nas_table_data*)
                                         snmpserv_get_data();
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_nas_table_get(subid, (*varp)->name, errp))
                    == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_NEXT:
                if (!nas_lookup_index(subid+1))
                        return -1;
                data->row = subid+1;
                break;
                        
        case MIB_NODE_RESET:
                data->row = 1; 
                break;

        case MIB_NODE_GET_SUBID:
                return data->row;

        case MIB_NODE_COMPARE:
                return 0;
                
        default: /* unused: should never get there */
                abort();

        }
        
        return 0;
        
}

struct snmp_var *
snmp_nas_table_get(subid, oid, errp)
        subid_t subid;
        oid_t oid;
        int *errp;
{
        struct snmp_var *ret;
        subid_t key;
        NAS *nas;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (key = SUBID(oid, OIDLEN(oid)-2)) {
        case MIB_KEY_NASAddress:
        case MIB_KEY_NASID:
        case MIB_KEY_NASLines:
        case MIB_KEY_NASLinesInUse:
        case MIB_KEY_NASLinesIdle:
                if ((nas = nas_lookup_index(subid)) != NULL && nas->app_data) {
                        get_stat_nasstat(nas, ret, key);
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
get_stat_nasstat(nas, var, ind)
        NAS *nas;
        struct snmp_var *var;
        int ind;
{
        struct nas_stat *statp = nas->app_data;
        
        switch (ind) {
        case MIB_KEY_NASAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(UINT4);
                var->var_str = snmp_alloc(sizeof(UINT4));
                *(UINT4*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_NASID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_NASLines:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->ports_active +
                               statp->ports_idle;
                break;

        case MIB_KEY_NASLinesInUse:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->ports_active;
                break;

        case MIB_KEY_NASLinesIdle:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = statp->ports_idle;
                break;

        }
}

/*ARGSUSED*/
int
snmp_port_index1(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        NAS *nas;
        struct port_data *pind = (struct port_data*)snmpserv_get_data();
        
        switch (cmd) {
        case MIB_NODE_GET:
                *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE:
                pind->nas_index = subid;
                return 0;
                
        case MIB_NODE_NEXT:
                return  -1; 
                
        case MIB_NODE_GET_SUBID:
                return pind->nas_index;
                
        case MIB_NODE_RESET:
                pind->nas_index = 1;
                while ((nas = nas_lookup_index(pind->nas_index)) && 
                       (pind->port_no = stat_get_next_port_no(nas, 0)) == 0)
                        pind->nas_index++;
                break; 
        }
        
        return 0;
}

int
snmp_port_index2(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        NAS *nas;
        int index;
        struct snmp_var *var;
        struct port_data *pind = (struct port_data*)snmpserv_get_data();
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((nas = nas_lookup_index(pind->nas_index)) == NULL ||
                    (index = stat_get_port_index(nas, pind->port_no)) == 0) {
                        *errp = SNMP_ERR_NOSUCHNAME;
                        return -1;
                }
                *errp = SNMP_ERR_NOERROR;
                var = snmp_var_create((*varp)->name);
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = index;
                *varp = var;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE:
                pind->port_no = subid;
                return 0;
                
        case MIB_NODE_NEXT:
                if ((nas = nas_lookup_index(pind->nas_index)) == NULL)
                        return -1;
                index = stat_get_next_port_no(nas, pind->port_no);
                if (index > 0) {
                        pind->port_no = index;
                        break;
                }
                /* move to next nas */
                while ((nas = nas_lookup_index(++pind->nas_index)) && 
                       (pind->port_no = stat_get_next_port_no(nas, 0)) == 0)
                        ;

                if (nas && pind->port_no > 0)
                        break;

                return -1;
                
        case MIB_NODE_GET_SUBID:
                return pind->port_no;
                
        case MIB_NODE_RESET:
                break; 
        }
        
        return 0;
}

struct snmp_var *snmp_port_get(subid_t subid, struct snmp_var *var, int *errp);
void get_port_stat(PORT_STAT *port, struct snmp_var *var, subid_t key);

int
snmp_port_table(cmd, unused, subid, varp, errp)
        enum mib_node_cmd cmd;
        void *unused;
        subid_t subid;
        struct snmp_var **varp;
        int *errp;
{
        struct port_table_data *p = (struct port_table_data*)
                                         snmpserv_get_data();
        
        switch (cmd) {
        case MIB_NODE_GET:
                if ((*varp = snmp_port_get(subid, *varp, errp)) == NULL)
                        return -1;
                break;
                
        case MIB_NODE_SET:
        case MIB_NODE_SET_TRY:
                /* None of these can be set */
                if (errp)
                        *errp = SNMP_ERR_NOSUCHNAME;
                return -1;
                
        case MIB_NODE_COMPARE: 
                return 0;
                
        case MIB_NODE_NEXT:
                if (findportbyindex(subid+1)) {
                        p->port_index = subid+1;
                        return 0;
                }
                return -1;
                
        case MIB_NODE_GET_SUBID:
                return p->port_index;
                
        case MIB_NODE_RESET:
                p->port_index = 1;
                break;

        }
        
        return 0;
}

struct snmp_var *
snmp_port_get(subid, var, errp)
        subid_t subid;
        struct snmp_var *var;
        int *errp;
{
        struct snmp_var *ret;
        subid_t key;
        oid_t oid = var->name;
        PORT_STAT *port;
        
        ret = snmp_var_create(oid);
        *errp = SNMP_ERR_NOERROR;

        switch (key = SUBID(oid, OIDLEN(oid)-2)) {

        case MIB_KEY_StatPortNASIndex:
        case MIB_KEY_StatPortID:
        case MIB_KEY_StatPortFramedAddress:
        case MIB_KEY_StatPortTotalLogins:                 
        case MIB_KEY_StatPortStatus:        
        case MIB_KEY_StatPortStatusChangeTimestamp:             
        case MIB_KEY_StatPortUpTime:         
        case MIB_KEY_StatPortLastLoginName:             
        case MIB_KEY_StatPortLastLoginTimestamp:      
        case MIB_KEY_StatPortLastLogoutTimestamp:      
        case MIB_KEY_StatPortIdleTotalTime:     
        case MIB_KEY_StatPortIdleMaxTime:      
        case MIB_KEY_StatPortIdleMaxTimestamp:        
        case MIB_KEY_StatPortInUseTotalTime:        
        case MIB_KEY_StatPortInUseMaxTime:     
        case MIB_KEY_StatPortInUseMaxTimestamp:       
                if (port = findportbyindex(subid)) {
                        get_port_stat(port, ret, key);
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

#define TDIFF(tv, time) (tv.tv_sec - time)*100 + tv.tv_usec/10000;

void
get_port_stat(port, var, key)
        PORT_STAT *port;
        struct snmp_var *var;
        subid_t key;
{
        struct timeval tv;
        struct timezone tz;
        NAS *nas;
        
        switch (key) {

        case MIB_KEY_StatPortNASIndex:
                nas = nas_lookup_ip(port->ip);
                var->type = ASN_INTEGER;
                var->val_length = sizeof(counter);
                if (nas && nas->app_data) {
                        struct nas_stat *nsp = nas->app_data;
                        var->var_int = nsp->index;
                } else
                        var->var_int = 0;
                break;

        case MIB_KEY_StatPortID:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(counter);
                var->var_int = port->port_no;
                break;

        case MIB_KEY_StatPortFramedAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(UINT4);
                var->var_str = snmp_alloc(sizeof(UINT4));
                *(UINT4*)var->var_str = port->framed_address;
                break;

        case MIB_KEY_StatPortTotalLogins:                 
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(counter);
                var->var_int = port->count;
                break;
                
        case MIB_KEY_StatPortStatus:        
                var->type = ASN_INTEGER;
                var->val_length = sizeof(counter);
                var->var_int = port->active ? port_active : port_idle;
                break;

        case MIB_KEY_StatPortStatusChangeTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->start;
                break;

        case MIB_KEY_StatPortUpTime:         
                gettimeofday(&tv, &tz);
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(counter);
                var->var_int = TDIFF(tv, port->start);
                break;
                
        case MIB_KEY_StatPortLastLoginName:             
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(port->login);
                var->var_str = snmp_strdup(port->login);
                break;

        case MIB_KEY_StatPortLastLoginTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->lastin;
                break;

        case MIB_KEY_StatPortLastLogoutTimestamp:      
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->lastout;
                break;

        case MIB_KEY_StatPortIdleTotalTime:     
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(counter);
                var->var_int = port->idle * 100;
                break;
                
        case MIB_KEY_StatPortIdleMaxTime:      
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(counter);
                var->var_int = port->maxidle.time * 100;
                break;
                
        case MIB_KEY_StatPortIdleMaxTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->maxidle.start;
                break;

        case MIB_KEY_StatPortInUseTotalTime:        
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(counter);
                var->var_int = port->inuse * 100;
                break;
                
        case MIB_KEY_StatPortInUseMaxTime:     
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(counter);
                var->var_int = port->maxinuse.time * 100;
                break;
                
        case MIB_KEY_StatPortInUseMaxTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->maxinuse.start;
                break;
        }
}

NAS *
nas_lookup_index(ind)
        int ind;
{
        NAS *nas;
        struct nas_stat *ns;
        
        for (nas = nas_next(NULL); nas; nas = nas_next(nas)) {
                ns = nas->app_data;
                if (ns && ns->index == ind)
                        break;
        }
        return nas;
}


#endif





