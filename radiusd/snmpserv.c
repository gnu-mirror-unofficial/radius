/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2006,
   2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#ifdef USE_SNMP

#include <sys/types.h>
#include <sys/socket.h>

#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <snmp/mib.h>

#include <sysdep.h>
#include <radiusd.h>
#include <radius/radutmp.h>
#include <radsnmp.h>
#define SERVER
#include <radmibs.h>

#define MAXOIDLEN 512
 
struct snmp_pdu * snmp_agent_response(struct snmp_pdu *pdu, int access);
int variable_cmp(struct snmp_var *v1, struct snmp_var *v2);
static grad_nas_t *nas_lookup_index(int ind);
static void snmpserv_before_config_hook(void *unused1, void *unused2);
static void snmpserv_after_config_hook(void *arg, void *unused);
static void snmp_tree_init();

static grad_list_t /* of ACL */ *snmp_acl;
static grad_list_t /* of Community */ *commlist;
Server_stat *server_stat;
struct radstat radstat;

/* ************************************************************************ */
/* Configuration file */

static grad_list_t /* of NETNAME */ *netlist;

static int
_netname_cmp(const void *item, const void *data)
{
	const NETNAME *p = item;
	const char *name = data;
	return strcmp(p->name, name);
}

static NETNAME *
netname_find(char *name)
{
        return grad_list_locate(netlist, name, _netname_cmp);
}

static int
_netdef_destroy(void *item, void *data ARG_UNUSED)
{
	grad_free(item);
	return 0;
}

static int
_netname_destroy(void *item, void *data ARG_UNUSED)
{
	NETNAME *p = item;
	grad_free(p->name);
	grad_list_destroy(&p->netlist, _netdef_destroy, NULL);
	grad_free(p);
	return 0;
}

static void
netgrad_list_destroy()
{
	grad_list_destroy(&netlist, _netname_destroy, NULL);
}

/* ************************************************************************ */
/* ACL fiddling */

void
snmp_add_community(char *str, int access)
{
        Community *p = grad_emalloc(sizeof(*p));
        p->name = grad_estrdup(str);
        p->access = access;
	if (!commlist)
		commlist = grad_list_create();
        grad_list_append(commlist, p);
}


static int
_community_cmp(const void *item, const void *data)
{
        const Community *p = item;
	return strcmp(p->name, (const char*) data);
}


Community *
snmp_find_community(char *str)
{
	return grad_list_locate(commlist, str, _community_cmp);
}

static int
_community_destroy(void *item, void *data)
{
	Community *p = item;
	grad_free(p->name);
	grad_free(p);
	return 0;
}

void
snmp_free_communities()
{
	grad_list_destroy(&commlist, _community_destroy, NULL);
}

struct acl_closure {
	grad_uint32_t ip;
	char *community;
	int access;
};

int
_netdef_cmp(const void *item, const void *data)
{
	const grad_netdef_t *nd = item;
	const struct acl_closure *clos = data;

	if (grad_ip_in_net_p(nd, clos->ip))
		return 0;
	return 1;
}

int
_acl_iterator(void *item, void *data)
{
	ACL *acl = item;
	struct acl_closure *clos = data;

	if (acl->community
	    && strcmp(acl->community->name, clos->community))
		return 0;
	if (grad_list_locate(acl->netlist, data, _netdef_cmp)) {
		clos->access = acl->community ? acl->community->access : 0;
		return 1;
	}
	return 0;
}

int
check_acl(grad_uint32_t ip, char *community)
{
	struct acl_closure clos;

	clos.ip = ntohl(ip);
	clos.community = community;
	clos.access = 0;
	grad_list_iterate(snmp_acl, _acl_iterator, &clos);
        return clos.access;
}

void
snmp_add_acl(Community *community, grad_list_t /* of grad_netdef_t */ *netlist)
{
        ACL *acl;

	acl = grad_emalloc(sizeof(*acl));
	acl->community = community;
	acl->netlist = netlist;
	if (!snmp_acl)
		snmp_acl = grad_list_create();
	grad_list_append(snmp_acl, acl);
}

static int
_acl_destroy(void *item, void *data)
{
	grad_free(item);
	return 0;
}
		
void
snmp_free_acl()
{
	grad_list_destroy(&snmp_acl, _acl_destroy, NULL);
}


/* ************************************************************************* */
static int _opened_snmp_sockets;

int
snmp_stmt_begin(int finish, void *data, void *up_data)
{
	if (!finish) {
		netgrad_list_destroy();
		snmp_free_communities();
		snmp_free_acl();
		_opened_snmp_sockets = 0;
	} else if (radius_mode == MODE_DAEMON
		   && !_opened_snmp_sockets
		   && snmp_port) 
		udp_open(R_SNMP, INADDR_ANY, snmp_port, 1);
	return 0;
}

static int
snmp_cfg_ident(int argc, cfg_value_t *argv, void *block_data,
	       void *handler_data)
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
		grad_free(server_id);
	server_id = grad_estrdup(argv[1].v.string);
	return 0;
}

static grad_keyword_t snmp_access[] = {
	{ "read-only", SNMP_RO },
	{ "read-write", SNMP_RW },
	{ "ro", SNMP_RO },
	{ "rw", SNMP_RW },
	{ 0 }
};

static int
snmp_cfg_community(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data)
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

	access = grad_xlat_keyword(snmp_access, argv[2].v.string, -1);
	if (access == -1) 
		return 1;
		
	if (snmp_find_community(argv[1].v.string)) {
		grad_log(GRAD_LOG_ERR,
		         _("%s:%d: community %s already declared"),
		         cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}
	
	snmp_add_community(argv[1].v.string, access);
	return 0;
}

int
snmp_cfg_listen(int argc, cfg_value_t *argv,
		void *block_data, void *handler_data)
{
	int i, errcnt = 0;
	
	if (argc == 2 && argv[1].type == CFG_BOOLEAN) {
		if (argv[1].v.bool == 0)
			snmp_port = 0;
		return 0;
	}
	
	for (i = 1; i < argc; i++) 
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) 
		for (i = 1; i < argc; i++) 
			udp_open(R_SNMP,
				 argv[i].v.host.ipaddr,
				 argv[i].v.host.port > 0 ?
				 argv[i].v.host.port : snmp_port,
				 1);
	_opened_snmp_sockets++;
	return 0;
}

static int
snmp_cfg_network(int argc, cfg_value_t *argv,
		 void *block_data, void *handler_data)
{
	int i;
	NETNAME *np;
	
	if (argc < 3) {
		cfg_argc_error(1);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

        np = grad_emalloc(sizeof(*np));
	if (!netlist) 
		netlist = grad_list_create(netlist);
		
	grad_list_append(netlist, np);
        np->name = grad_estrdup(argv[1].v.string);
	np->netlist = grad_list_create();
	for (i = 2; i < argc; i++) {
		if (argv[i].type != CFG_NETWORK) {
			grad_log(GRAD_LOG_ERR,
			         _("%s:%d: list item %d has wrong datatype"),
			         cfg_filename, cfg_line_num,
			         i);
		} else {
			grad_netdef_t *net = grad_emalloc(sizeof(*net));
			net->ipaddr = argv[i].v.network.ipaddr;
			net->netmask = argv[i].v.network.netmask;
			grad_list_append(np->netlist, net);
		}
	}
	return 0;
}

static int
snmp_cfg_allow(int argc, cfg_value_t *argv,
	       void *block_data, void *handler_data)
{
	Community *comm;
	NETNAME *nn;
	
	if (argc != 3) {
		cfg_argc_error(argc < 3);
		return 0;
	}
	
 	if (argv[1].type != CFG_STRING || argv[2].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	if ((nn = netname_find(argv[1].v.string)) == NULL) {
		grad_log(GRAD_LOG_ERR, _("%s:%d: no such network: %s"),
		         cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}

	comm = snmp_find_community(argv[2].v.string);
	if (!comm) {
		grad_log(GRAD_LOG_ERR, 
		         _("%s:%d: undefined community %s"),
		         cfg_filename, cfg_line_num, argv[2].v.string);
		return 0;
	} 

	snmp_add_acl(comm, nn->netlist);
	return 0;
}

static int
snmp_cfg_deny(int argc, cfg_value_t *argv,
	      void *block_data, void *handler_data)
{
	NETNAME *nn;
	
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
	
 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	if ((nn = netname_find(argv[1].v.string)) == NULL) {
		grad_log(GRAD_LOG_ERR, _("%s:%d: no such network: %s"),
		         cfg_filename, cfg_line_num, argv[1].v.string);
		return 0;
	}

	snmp_add_acl(NULL, nn->netlist);
	return 0;
}

static struct cfg_stmt acl_stmt[] = {
	{ "allow", CS_STMT, NULL, snmp_cfg_allow, NULL, NULL, NULL },
	{ "deny", CS_STMT, NULL, snmp_cfg_deny, NULL, NULL, NULL },
	{ NULL },
};

struct cfg_stmt snmp_stmt[] = {
	{ "port", CS_STMT, NULL, cfg_get_port, &snmp_port, NULL, NULL },
	{ "listen", CS_STMT, NULL, snmp_cfg_listen, NULL, NULL, NULL },
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
	{ "storage", CS_BLOCK, NULL, NULL, NULL,
	  storage_stmt, NULL },
	{ "network", CS_STMT, NULL, snmp_cfg_network, NULL,
	  NULL, NULL },
	{ "acl", CS_BLOCK, NULL, NULL, NULL, acl_stmt, NULL },
	/* Obsolete statements */
	{ "spawn", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
	{ NULL, }
};

static void
snmpserv_before_config_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	if (server_stat) {
		server_stat->auth.status = serv_init;
		server_stat->acct.status = serv_init;
	}
}

static void
snmpserv_after_config_hook(void *arg, void *data ARG_UNUSED)
{
	stat_done();
	stat_init();
	if (server_stat) {
		grad_nas_t *nas;
		grad_iterator_t *itr;
	
		server_stat->auth.status =
			suspend_flag ? serv_suspended : serv_running;
		snmp_auth_server_reset();

		server_stat->acct.status = server_stat->auth.status;
		snmp_acct_server_reset();
                
		*(serv_stat*)arg = server_stat->auth.status;
		snmp_init_nas_stat();
		itr = grad_nas_iterator();
		for (nas = grad_iterator_first(itr); nas; nas = grad_iterator_next(itr))
			snmp_attach_nas_stat(nas);
		grad_iterator_destroy(&itr);
		snmp_sort_nas_stat();
	}
}

void
snmpserv_init(void *arg)
{
	stat_init();
	radiusd_set_preconfig_hook(snmpserv_before_config_hook, NULL, 0);
	radiusd_set_postconfig_hook(snmpserv_after_config_hook, arg, 0);
	snmp_tree_init();
	snmpserv_after_config_hook(arg, NULL);
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

union snmpserv_data {
        struct auth_mib_data auth_mib;
        struct nas_data nas;
        struct nas_table_data nas_data;
        struct port_data port;
        struct port_table_data port_table;
};

static union snmpserv_data *__snmpserv_data;

static void *
snmpserv_get_data()
{
        if (!__snmpserv_data) {
                __snmpserv_data = grad_emalloc(sizeof(*__snmpserv_data));
                __snmpserv_data->auth_mib.nas_index = 1;
        }
        return __snmpserv_data;
}

static struct mib_data {
        oid_t oid;
        mib_fp handler;
        void *closure;
} mib_data[] = {
        /* Authentication */
        /* Fixed oids */
        { oid_AuthServIdent,                   snmp_auth_handler, NULL },
        { oid_AuthServUpTime,                  snmp_auth_handler, NULL },
        { oid_AuthServResetTime,               snmp_auth_handler, NULL },
        { oid_AuthServConfigReset,             snmp_auth_handler, NULL },
        { oid_AuthServTotalAccessRequests,     snmp_auth_handler, NULL },
        { oid_AuthServTotalInvalidRequests,    snmp_auth_handler, NULL },
        { oid_AuthServTotalDupAccessRequests,  snmp_auth_handler, NULL },
        { oid_AuthServTotalAccessAccepts,      snmp_auth_handler, NULL },
        { oid_AuthServTotalAccessRejects,      snmp_auth_handler, NULL },
        { oid_AuthServTotalAccessChallenges,   snmp_auth_handler, NULL }, 
        { oid_AuthServTotalMalformedAccessRequests,
                                             snmp_auth_handler, NULL },
        { oid_AuthServTotalBadAuthenticators,  snmp_auth_handler, NULL },
        { oid_AuthServTotalPacketsDropped,     snmp_auth_handler, NULL },
        { oid_AuthServTotalUnknownTypes,       snmp_auth_handler, NULL },

        /* Variable oids */
        { oid_AuthClientIndex,                 snmp_auth_v_handler,NULL },
        { oid_AuthClientAddress,               snmp_auth_v_handler,NULL },
        { oid_AuthClientID,                    snmp_auth_v_handler,NULL },
        { oid_AuthServAccessRequests,          snmp_auth_v_handler,NULL },
        { oid_AuthServDupAccessRequests,       snmp_auth_v_handler,NULL },
        { oid_AuthServAccessAccepts,           snmp_auth_v_handler,NULL },
        { oid_AuthServAccessRejects,           snmp_auth_v_handler,NULL },
        { oid_AuthServAccessChallenges,        snmp_auth_v_handler,NULL },
        { oid_AuthServMalformedAccessRequests, snmp_auth_v_handler,NULL },
        { oid_AuthServBadAuthenticators,       snmp_auth_v_handler,NULL },
        { oid_AuthServPacketsDropped,          snmp_auth_v_handler,NULL },
        { oid_AuthServUnknownTypes,            snmp_auth_v_handler,NULL },
        
        /* Accounting */
        /* Fixed oids */
        { oid_AccServIdent,                    snmp_acct_handler, NULL },
        { oid_AccServUpTime,                   snmp_acct_handler, NULL },
        { oid_AccServResetTime,                snmp_acct_handler, NULL },
        { oid_AccServConfigReset,              snmp_acct_handler, NULL },
        { oid_AccServTotalRequests,            snmp_acct_handler, NULL },
        { oid_AccServTotalInvalidRequests,     snmp_acct_handler, NULL },    
        { oid_AccServTotalDupRequests,         snmp_acct_handler, NULL },      
        { oid_AccServTotalResponses,           snmp_acct_handler, NULL },      
        { oid_AccServTotalMalformedRequests,   snmp_acct_handler, NULL },      
        { oid_AccServTotalBadAuthenticators,   snmp_acct_handler, NULL },      
        { oid_AccServTotalPacketsDropped,      snmp_acct_handler, NULL },      
        { oid_AccServTotalNoRecords,           snmp_acct_handler, NULL },      
        { oid_AccServTotalUnknownTypes,        snmp_acct_handler, NULL },      

        /* Variable oids */
        { oid_AccClientIndex,                  snmp_acct_v_handler,NULL },
        { oid_AccClientAddress,                snmp_acct_v_handler,NULL },
        { oid_AccClientID,                     snmp_acct_v_handler,NULL },
        { oid_AccServPacketsDropped,           snmp_acct_v_handler,NULL },
        { oid_AccServRequests,                 snmp_acct_v_handler,NULL },
        { oid_AccServDupRequests,              snmp_acct_v_handler,NULL },
        { oid_AccServResponses,                snmp_acct_v_handler,NULL },
        { oid_AccServBadAuthenticators,        snmp_acct_v_handler,NULL },
        { oid_AccServMalformedRequests,        snmp_acct_v_handler,NULL },
        { oid_AccServNoRecords,                snmp_acct_v_handler,NULL },
        { oid_AccServUnknownTypes,             snmp_acct_v_handler,NULL },

#ifdef SNMP_COMPAT_0_96
        
        /* Server */
        { oid_grad_radiusServerUpTime,         snmp_serv_handler, NULL },
        { oid_grad_radiusServerResetTime,      snmp_serv_handler, NULL },
        { oid_grad_radiusServerState,          snmp_serv_handler, NULL },

        
        /* Statistics */
        { oid_grad_StatIdent,             snmp_stat_handler, NULL },
        { oid_grad_StatUpTime,            snmp_stat_handler, NULL },
        { oid_grad_StatConfigReset,       snmp_stat_handler, NULL },
        { oid_grad_StatTotalLines,        snmp_stat_handler, NULL },
        { oid_grad_StatTotalLinesInUse,   snmp_stat_handler, NULL },
        { oid_grad_StatTotalLinesIdle,    snmp_stat_handler, NULL },

        /* Variable oids */
        { oid_grad_NASIndex1,             snmp_stat_nas1, NULL },
        { oid_grad_NASIndex2,             snmp_stat_nas2, NULL },
        { oid_grad_NASIndex3,             snmp_stat_nas3, NULL },
        { oid_grad_NASIndex4,             snmp_stat_nas4, NULL },

        { oid_grad_NASAddress,            snmp_nas_table, NULL },
        { oid_grad_NASID,                 snmp_nas_table, NULL },
        { oid_grad_NASLines,              snmp_nas_table, NULL },
        { oid_grad_NASLinesInUse,         snmp_nas_table, NULL },
        { oid_grad_NASLinesIdle,          snmp_nas_table, NULL },

        { oid_grad_StatPortIndex1,        snmp_port_index1, NULL },
        { oid_grad_StatPortIndex2,        snmp_port_index2, NULL },

        /* port table */
        { oid_grad_StatPortNASIndex,      snmp_port_table, NULL },
        { oid_grad_StatPortID,            snmp_port_table, NULL },
        { oid_grad_StatPortFramedAddress, snmp_port_table, NULL },
        { oid_grad_StatPortTotalLogins,   snmp_port_table, NULL },
        { oid_grad_StatPortStatus,        snmp_port_table, NULL },
        { oid_grad_StatPortStatusChangeTimestamp,   snmp_port_table, NULL },
        { oid_grad_StatPortUpTime,        snmp_port_table, NULL },
        { oid_grad_StatPortLastLoginName, snmp_port_table, NULL },
        { oid_grad_StatPortLastLoginTimestamp,  snmp_port_table, NULL },
        { oid_grad_StatPortLastLogoutTimestamp, snmp_port_table, NULL },
        { oid_grad_StatPortIdleTotalTime, snmp_port_table, NULL },
        { oid_grad_StatPortIdleMaxTime,   snmp_port_table, NULL },
        { oid_grad_StatPortIdleMaxTimestamp, snmp_port_table, NULL },
        { oid_grad_StatPortInUseTotalTime, snmp_port_table, NULL },
        { oid_grad_StatPortInUseMaxTime,   snmp_port_table, NULL },
        { oid_grad_StatPortInUseMaxTimestamp, snmp_port_table, NULL },
#endif
        /* enterprise.gnu.radius subtree */
        /* Server */
        { oid_radiusServerUpTime,         snmp_serv_handler, NULL },
        { oid_radiusServerResetTime,      snmp_serv_handler, NULL },
        { oid_radiusServerState,          snmp_serv_handler, NULL },


        /* Statistics */
        { oid_StatIdent,                       snmp_stat_handler, NULL },
        { oid_StatUpTime,                      snmp_stat_handler, NULL },
        { oid_StatConfigReset,                 snmp_stat_handler, NULL },
        { oid_StatTotalLines,                  snmp_stat_handler, NULL },
        { oid_StatTotalLinesInUse,             snmp_stat_handler, NULL },
        { oid_StatTotalLinesIdle,              snmp_stat_handler, NULL },

        /* Variable oids */
        { oid_NASIndex1,                       snmp_stat_nas1, NULL },
        { oid_NASIndex2,                       snmp_stat_nas2, NULL },
        { oid_NASIndex3,                       snmp_stat_nas3, NULL },
        { oid_NASIndex4,                       snmp_stat_nas4, NULL },

        { oid_NASAddress,                      snmp_nas_table, NULL },
        { oid_NASID,                           snmp_nas_table, NULL },
        { oid_NASLines,                        snmp_nas_table, NULL },
        { oid_NASLinesInUse,                   snmp_nas_table, NULL },
        { oid_NASLinesIdle,                    snmp_nas_table, NULL },

        { oid_StatPortIndex1,                  snmp_port_index1, NULL },
        { oid_StatPortIndex2,                  snmp_port_index2, NULL },

        /* port table */
        { oid_StatPortNASIndex,                snmp_port_table, NULL },
        { oid_StatPortID,                      snmp_port_table, NULL },
        { oid_StatPortFramedAddress,           snmp_port_table, NULL },
        { oid_StatPortTotalLogins,             snmp_port_table, NULL },
        { oid_StatPortStatus,                  snmp_port_table, NULL },
        { oid_StatPortStatusChangeTimestamp,   snmp_port_table, NULL },
        { oid_StatPortUpTime,                  snmp_port_table, NULL },
        { oid_StatPortLastLoginName,           snmp_port_table, NULL },
        { oid_StatPortLastLoginTimestamp,      snmp_port_table, NULL },
        { oid_StatPortLastLogoutTimestamp,     snmp_port_table, NULL },
        { oid_StatPortIdleTotalTime,           snmp_port_table, NULL },
        { oid_StatPortIdleMaxTime,             snmp_port_table, NULL },
        { oid_StatPortIdleMaxTimestamp,        snmp_port_table, NULL },
        { oid_StatPortInUseTotalTime,          snmp_port_table, NULL },
        { oid_StatPortInUseMaxTime,            snmp_port_table, NULL },
        { oid_StatPortInUseMaxTimestamp,       snmp_port_table, NULL },

};                                          

void
snmp_tree_init()
{
        struct mib_data *p;
        struct mib_node_t *node;
        
        snmp_init(0, 0, (snmp_alloc_t)grad_emalloc, (snmp_free_t)grad_free);

        for (p = mib_data; p < mib_data + GRAD_NITEMS(mib_data); p++) {
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
mib_node_oid(struct mib_node_t *node)
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
mib_reset(struct mib_node_t *node)
{
        if (node->subid == SUBID_X) {
                (*node->handler)(MIB_NODE_RESET, node->closure,
                                 0,
                                 NULL, NULL);
        }
}
                
int
mib_down(struct mib_node_t *node, oid_t oid)
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
mib_get_next(struct mib_node_t *node, struct snmp_var **varp, int *errp)
{
        int rc;
        oid_t oid = (*varp)->name;
        char buf[MAXOIDLEN];
        struct snmp_var *temp_var;
        struct mib_node_t *found_node;
        
        GRAD_DEBUG1(2, "OID %s",
                    sprint_oid(buf, sizeof(buf), (*varp)->name));
        
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
                        GRAD_DEBUG2(2, "rolling back from %d:%d",
                                    found_node->index,
                                    found_node->subid);
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
                                GRAD_DEBUG2(2, "rollback stopped at %d:%d",
                                            node->index,
                                            node->subid);

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

        GRAD_DEBUG1(2, "NXT %s", sprint_oid(buf, sizeof(buf), temp_var->name));
                         
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
mib_get(struct mib_node_t *node, struct snmp_var **varp, int *errp)
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
mib_set_try(struct mib_node_t *node, struct snmp_var **varp, int *errp)
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
mib_set(struct mib_node_t *node, struct snmp_var **varp)
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
snmp_agent_response(struct snmp_pdu *pdu, int access)
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
                        GRAD_DEBUG(1, "SetRequest-PDU");
                        if (access == SNMP_RO) {
                                answer->err_stat = SNMP_ERR_GENERR;
                                answer->err_ind = 1;
                                GRAD_DEBUG(1,"bad access mode");
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
                                GRAD_DEBUG(1, "returning error");
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

                        GRAD_DEBUG(1, "success");
                        return answer;

                case SNMP_PDU_GET:
                        GRAD_DEBUG(1, "GetRequest-PDU");

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
                                        GRAD_DEBUG(1,"returning");
                                        /* preserve the rest of vars */
                                        *vresp = snmp_var_dup_list(vp);
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
                        GRAD_DEBUG(1, "GetNextRequest-PDU");

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
                                        GRAD_DEBUG1(1, 
                                                    "returning: err_stat=%d",
						     answer->err_stat);
                                        /* preserve the rest of vars */
                                        *vresp = snmp_var_dup_list(vp);
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

grad_counter_t
timeval_diff(struct timeval *tva, struct timeval *tvb)
{
        return  (tva->tv_sec - tvb->tv_sec)*100 +
                (tva->tv_usec - tvb->tv_usec)/10000;
}

serv_stat
abridge_server_state()
{
        switch (server_stat->auth.status) {
        case serv_init:
        case serv_running:
                return server_stat->auth.status;
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
int
snmp_auth_handler(enum mib_node_cmd cmd, void *closure,
		  subid_t subid, struct snmp_var **varp, int *errp)
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
snmp_auth_var_get(subid_t subid, oid_t oid, int *errp)
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
                grad_free(p);
                break;

        case MIB_KEY_AuthServUpTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv, &server_stat->start_time);
                break;

        case MIB_KEY_AuthServResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv,
                                            &server_stat->auth.reset_time);
                break;

        case MIB_KEY_AuthServConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = abridge_server_state();
                break;

        case MIB_KEY_AuthServTotalAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_access_req;
                break;

        case MIB_KEY_AuthServTotalInvalidRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_invalid_req;
                break;

        case MIB_KEY_AuthServTotalDupAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_dup_req;
                break;

        case MIB_KEY_AuthServTotalAccessAccepts:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_accepts;
                break;

        case MIB_KEY_AuthServTotalAccessRejects:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_rejects;
                break;

        case MIB_KEY_AuthServTotalAccessChallenges:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_challenges;
                break;

        case MIB_KEY_AuthServTotalMalformedAccessRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_bad_req;
                break;

        case MIB_KEY_AuthServTotalBadAuthenticators:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_bad_auth;
                break;
                
        case MIB_KEY_AuthServTotalPacketsDropped:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.num_dropped;
                break;

        case MIB_KEY_AuthServTotalUnknownTypes:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
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
snmp_auth_var_set(subid_t subid, struct snmp_var **vp, int *errp)
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
                        server_stat->auth.status = serv_init;
                        grad_log(GRAD_LOG_INFO,
                                 _("acct server re-initializing on SNMP request"));
                        break;

                }
        }
        return (*vp == NULL);
}

/* Variable oids */

void get_auth_nasstat(grad_nas_t *nas, struct snmp_var *var, int ind);
int snmp_auth_v_handler(enum mib_node_cmd cmd, void *closure,
                        subid_t subid, struct snmp_var **varp,
                        int *errp);
struct snmp_var *snmp_auth_var_v_get(subid_t subid, struct snmp_var *var,
                                     int *errp);
int snmp_auth_var_next(subid_t subid, struct auth_mib_data *closure);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_auth_v_handler(enum mib_node_cmd cmd, void *unused, subid_t subid,
		    struct snmp_var **varp, int *errp)
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
snmp_auth_var_next(subid_t subid, struct auth_mib_data *closure)
{
        if (!nas_lookup_index(subid)) 
                return -1;

        closure->nas_index = subid;
        return 0;
}

struct snmp_var *
snmp_auth_var_v_get(subid_t subid, struct snmp_var *var, int *errp)
{
        struct snmp_var *ret;
        subid_t key;
        grad_nas_t *nas;
        
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
get_auth_nasstat(grad_nas_t *nas, struct snmp_var *var, int key)
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
                var->val_length = sizeof(grad_uint32_t);
                var->var_str = snmp_alloc(sizeof(grad_uint32_t));
                *(grad_uint32_t*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_AuthClientID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_AuthServAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_access_req;
                break;

        case MIB_KEY_AuthServDupAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_dup_req;
                break;

        case MIB_KEY_AuthServAccessAccepts:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_accepts;
                break;

        case MIB_KEY_AuthServAccessRejects:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_rejects;
                break;

        case MIB_KEY_AuthServAccessChallenges:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_challenges;
                break;

        case MIB_KEY_AuthServMalformedAccessRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_bad_req;
                break;

        case MIB_KEY_AuthServBadAuthenticators:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_bad_auth;
                break;

        case MIB_KEY_AuthServPacketsDropped:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_dropped;
                break;

        case MIB_KEY_AuthServUnknownTypes:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->auth.num_unknowntypes;
                break;
                
        }
}


/* ************************************************************************* */
/* Accounting sub-tree */
struct snmp_var *snmp_acct_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_acct_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */

int
snmp_acct_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
		  struct snmp_var **varp, int *errp)
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
snmp_acct_var_get(subid_t subid, oid_t oid, int *errp)
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
                grad_free(p);
                break;

        case MIB_KEY_AccServUpTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv, &server_stat->start_time);
                break;
                
        case MIB_KEY_AccServResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv, &server_stat->acct.reset_time);
                break;

        case MIB_KEY_AccServConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = abridge_server_state();
                break;
                
        case MIB_KEY_AccServTotalRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_req;
                break;
                
        case MIB_KEY_AccServTotalInvalidRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_invalid_req;
                break;
                
        case MIB_KEY_AccServTotalDupRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_dup_req;
                break;
                
        case MIB_KEY_AccServTotalResponses:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_resp;
                break;
                
        case MIB_KEY_AccServTotalMalformedRequests:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_bad_req;
                break;
                
        case MIB_KEY_AccServTotalBadAuthenticators:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_bad_sign;
                break;
                
        case MIB_KEY_AccServTotalPacketsDropped:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_dropped;
                break;
                
        case MIB_KEY_AccServTotalNoRecords:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->acct.num_norecords;
                break;
                
        case MIB_KEY_AccServTotalUnknownTypes:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
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
snmp_acct_var_set(subid_t subid, struct snmp_var **vp, int *errp)
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
                        grad_log(GRAD_LOG_INFO,
                                 _("auth server re-initializing on SNMP request"));
                        break;

                }
        }
        return (*vp == NULL);
}

void get_acct_nasstat(grad_nas_t *nas, struct snmp_var *var, int key);
int snmp_acct_v_handler(enum mib_node_cmd cmd, void *closure,
                        subid_t subid, struct snmp_var **varp,
                        int *errp);
struct snmp_var *snmp_acct_var_v_get(subid_t subid, struct snmp_var *var,
                                     int *errp);

/* Handler function for variable oid of the authentication subtree */ 
int
snmp_acct_v_handler(enum mib_node_cmd cmd, void *unused, subid_t subid,
		    struct snmp_var **varp, int *errp)
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
snmp_acct_var_v_get(subid_t subid, struct snmp_var *var, int *errp)
{
        struct snmp_var *ret;
        subid_t key;
        grad_nas_t *nas;
        
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
get_acct_nasstat(grad_nas_t *nas, struct snmp_var *var, int key)
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
                var->val_length = sizeof(grad_uint32_t);
                var->var_str = snmp_alloc(sizeof(grad_uint32_t));
                *(grad_uint32_t*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_AccClientID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_AccServPacketsDropped:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_dropped;
                break;

        case MIB_KEY_AccServRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_req;
                break;

        case MIB_KEY_AccServDupRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_dup_req;
                break;

        case MIB_KEY_AccServResponses:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_resp;
                break;

        case MIB_KEY_AccServBadAuthenticators:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_bad_sign;
                break;

        case MIB_KEY_AccServMalformedRequests:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_bad_req;
                break;

        case MIB_KEY_AccServNoRecords:
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_norecords;
                break;

        case MIB_KEY_AccServUnknownTypes:         
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->acct.num_unknowntypes;
                break;
        }
}

/* ************************************************************************* */
/* Server */
struct snmp_var *snmp_serv_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_serv_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the server subtree */

int
snmp_serv_handler(enum mib_node_cmd cmd, void *closure,
		  subid_t subid, struct snmp_var **varp, int *errp)
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
snmp_serv_var_get(subid_t subid, oid_t oid, int *errp)
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
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv, &server_stat->start_time);
                break;

        case MIB_KEY_radiusServerResetTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv,
                                            &server_stat->auth.reset_time);
                break;

        case MIB_KEY_radiusServerState:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = server_stat->auth.status;/*FIXME*/
                break;
        default:
                *errp = SNMP_ERR_NOSUCHNAME;
                snmp_var_free(ret);
                return NULL;
        }
        return ret;
}

int
snmp_serv_var_set(subid_t subid, struct snmp_var **vp, int *errp)
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
                        server_stat->auth.status = (*vp)->var_int;
                        switch ((*vp)->var_int) {
                        case serv_reset:
                                grad_log(GRAD_LOG_NOTICE,
                                         _("server re-initializing on SNMP request"));
                                break;
                        case serv_init:
                                grad_log(GRAD_LOG_NOTICE,
                                         _("server restart on SNMP request"));
                                break;
                        case serv_running:
                                grad_log(GRAD_LOG_NOTICE,
                                         _("server continuing on SNMP request"));
                                break;
                        case serv_suspended:
                                grad_log(GRAD_LOG_NOTICE,
                                         _("server suspending on SNMP request"));
                                break;
                        case serv_shutdown:
                                grad_log(GRAD_LOG_NOTICE,
                                         _("server shutting down on SNMP request"));
                                break;
                        }
                        break;

                }
        }
        return (*vp == NULL);
}


/* ************************************************************************* */
/* Statistics */
struct snmp_var *snmp_stat_var_get(subid_t subid, oid_t oid, int *errp);
int snmp_stat_var_set(subid_t subid, struct snmp_var **vp, int *errp);

/* Handler function for fixed oids from the authentication subtree */

int
snmp_stat_handler(enum mib_node_cmd cmd, void *closure, subid_t subid,
		  struct snmp_var **varp, int *errp)
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
snmp_stat_var_get(subid_t subid, oid_t oid, int *errp)
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
                grad_free(p);
                break;

        case MIB_KEY_StatUpTime:
                gettimeofday(&tv, &tz);
                ret->type = SMI_TIMETICKS;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = timeval_diff(&tv, &radstat.start_time);
                break;

        case MIB_KEY_StatConfigReset:
                ret->type = ASN_INTEGER;
                ret->val_length = sizeof(grad_counter_t);
                ret->var_int = serv_running;;
                break;

        case MIB_KEY_StatTotalLines:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                stat_count_ports();
                ret->var_int = radstat.port_active_count
                            + radstat.port_idle_count;
                break;

        case MIB_KEY_StatTotalLinesInUse:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
                stat_count_ports();
                ret->var_int = radstat.port_active_count;
                break;

        case MIB_KEY_StatTotalLinesIdle:
                ret->type = SMI_COUNTER32;
                ret->val_length = sizeof(grad_counter_t);
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
snmp_stat_nas(int num, enum mib_node_cmd cmd, struct nas_data *closure,
	      subid_t subid, struct snmp_var **varp, int *errp)
{
        grad_nas_t *nas;
        struct nas_stat *nsp;
        grad_uint32_t ip;
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

                if ((nas = grad_nas_lookup_ip(ip)) == NULL) {
                        return -1;
                }
                
                nsp = nas->app_data;
                if ((nas = nas_lookup_index(nsp->index+1)) == NULL) {
                        return -1;
                }

		/* FIXME: MIBS do not reflect netmask */
                for (num = 0; num < 4; num++)
                        closure->quad[num] = (nas->netdef.ipaddr >>
                                              (8*(3-num))) & 0xff;
                
                break;
                
        case MIB_NODE_GET_SUBID:
                return closure->quad[num];
                
        case MIB_NODE_RESET:
                if (num == 0) {
                        if (nas = nas_lookup_index(1))
                                for (num = 0; num < 4; num++)
                                        closure->quad[num] =
						(nas->netdef.ipaddr >>
                                                          (8*(3-num))) & 0xff;
                }
                break;

        }
        
        return 0;
}

int
snmp_stat_nas1(enum mib_node_cmd cmd, void *unused,
	       subid_t subid, struct snmp_var **varp, int *errp)
{
        return snmp_stat_nas(0, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas2(enum mib_node_cmd cmd, void *unused,
	       subid_t subid, struct snmp_var **varp, int *errp)
{
        return snmp_stat_nas(1, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas3(enum mib_node_cmd cmd, void *unused,
	       subid_t subid, struct snmp_var **varp, int *errp)
{
        return snmp_stat_nas(2, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}

int
snmp_stat_nas4(enum mib_node_cmd cmd, void *unused,
	       subid_t subid, struct snmp_var **varp, int *errp)
{
        return snmp_stat_nas(3, cmd,
                             (struct nas_data*)snmpserv_get_data(), subid,
                             varp, errp);
}


void get_stat_nasstat(grad_nas_t *nas, struct snmp_var *var, int ind);
struct snmp_var *snmp_nas_table_get(subid_t subid, oid_t oid, int *errp);

int
snmp_nas_table(enum mib_node_cmd cmd, void *unused,
	       subid_t subid, struct snmp_var **varp, int *errp)
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
snmp_nas_table_get(subid_t subid, oid_t oid, int *errp)
{
        struct snmp_var *ret;
        subid_t key;
        grad_nas_t *nas;
        
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
get_stat_nasstat(grad_nas_t *nas, struct snmp_var *var, int ind)
{
        struct nas_stat *statp = nas->app_data;
        
        switch (ind) {
        case MIB_KEY_NASAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(grad_uint32_t);
                var->var_str = snmp_alloc(sizeof(grad_uint32_t));
                *(grad_uint32_t*)var->var_str = ntohl(statp->ipaddr);
                break;

        case MIB_KEY_NASID:
                var->type = ASN_OCTET_STR;
                var->val_length = strlen(nas->longname);
                var->var_str = snmp_strdup(nas->longname);
                break;

        case MIB_KEY_NASLines:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->ports_active +
                               statp->ports_idle;
                break;

        case MIB_KEY_NASLinesInUse:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->ports_active;
                break;

        case MIB_KEY_NASLinesIdle:
                stat_count_ports();
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = statp->ports_idle;
                break;

        }
}

/*ARGSUSED*/
int
snmp_port_index1(enum mib_node_cmd cmd, void *unused,
		 subid_t subid, struct snmp_var **varp, int *errp)
{
        grad_nas_t *nas;
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
snmp_port_index2(enum mib_node_cmd cmd, void *unused,
		 subid_t subid, struct snmp_var **varp, int *errp)
{
        grad_nas_t *nas;
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
snmp_port_table(enum mib_node_cmd cmd, void *unused,
		subid_t subid, struct snmp_var **varp, int *errp)
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
snmp_port_get(subid_t subid, struct snmp_var *var, int *errp)
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
get_port_stat(PORT_STAT *port, struct snmp_var *var, subid_t key)
{
        struct timeval tv;
        struct timezone tz;
        grad_nas_t *nas;
        
        switch (key) {

        case MIB_KEY_StatPortNASIndex:
                nas = grad_nas_lookup_ip(port->ip);
                var->type = ASN_INTEGER;
                var->val_length = sizeof(grad_counter_t);
                if (nas && nas->app_data) {
                        struct nas_stat *nsp = nas->app_data;
                        var->var_int = nsp->index;
                } else
                        var->var_int = 0;
                break;

        case MIB_KEY_StatPortID:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->port_no;
                break;

        case MIB_KEY_StatPortFramedAddress:
                var->type = SMI_IPADDRESS;
                var->val_length = sizeof(grad_uint32_t);
                var->var_str = snmp_alloc(sizeof(grad_uint32_t));
                *(grad_uint32_t*)var->var_str = port->framed_address;
                break;

        case MIB_KEY_StatPortTotalLogins:                 
                var->type = SMI_COUNTER32;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->count;
                break;
                
        case MIB_KEY_StatPortStatus:        
                var->type = ASN_INTEGER;
                var->val_length = sizeof(grad_counter_t);
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
                var->val_length = sizeof(grad_counter_t);
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
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->idle * 100;
                break;
                
        case MIB_KEY_StatPortIdleMaxTime:      
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->maxidle.time * 100;
                break;
                
        case MIB_KEY_StatPortIdleMaxTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->maxidle.start;
                break;

        case MIB_KEY_StatPortInUseTotalTime:        
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->inuse * 100;
                break;
                
        case MIB_KEY_StatPortInUseMaxTime:     
                var->type = SMI_TIMETICKS;
                var->val_length = sizeof(grad_counter_t);
                var->var_int = port->maxinuse.time * 100;
                break;
                
        case MIB_KEY_StatPortInUseMaxTimestamp:
                var->type = ASN_INTEGER;
                var->val_length = sizeof(int);
                var->var_int = port->maxinuse.start;
                break;
        }
}

grad_nas_t *
nas_lookup_index(int ind)
{
        grad_nas_t *nas;
	grad_iterator_t *itr = grad_nas_iterator();
        struct nas_stat *ns;
        
        for (nas = grad_iterator_first(itr); nas; nas = grad_iterator_next(itr)) {
                ns = nas->app_data;
                if (ns && ns->index == ind)
                        break;
        }
	grad_iterator_destroy(&itr);
        return nas;
}


/* *********************** SNMP Protocol Interface ************************* */

/* Decode the SNMP request */
static int
snmp_decode(SNMP_REQ *req, u_char *buf, size_t len)
{
        struct snmp_pdu *pdu;
        struct snmp_session sess;
        int access;
        char comm[128];
        int comm_len;
        char ipbuf[GRAD_IPV4_STRING_LENGTH];
        
        log_open(GRAD_LOG_SNMP);
	
        if ((pdu = snmp_pdu_create(0)) == NULL) {
                grad_log(GRAD_LOG_ERR,
                         _("can't create SNMP PDU: %s"),
                         snmp_strerror(snmp_errno));
                return -1;
        }
        comm_len = sizeof(comm);
        if (snmp_decode_request(&sess, pdu, buf, len, comm, &comm_len)) {
                grad_log(GRAD_LOG_ERR,
                         _("can't decode SNMP packet from %s: %s"),
		         grad_ip_iptostr(ntohl(req->addr.sin_addr.s_addr),
				         ipbuf),
		         snmp_strerror(snmp_errno));
                return -1;
        }

        access = check_acl(req->addr.sin_addr.s_addr, comm);
        if (!access) {
                grad_log(GRAD_LOG_NOTICE,
                         _("DENIED attempt to access community %s from %s"),
                         comm,
                         grad_ip_iptostr(ntohl(req->addr.sin_addr.s_addr), 
                                         ipbuf));
                return 1;
        }
        req->pdu = pdu;
        req->community = grad_estrdup(comm);
        req->access = access;
        return 0;
}

int
snmp_req_decode(const struct sockaddr_in *srv_sa,
		const struct sockaddr_in *clt_sa,
		void *input, size_t inputsize, void **output)
{
        SNMP_REQ *req;

	req = grad_emalloc(sizeof *req);
	req->addr = *clt_sa;
        if (snmp_decode(req, input, inputsize)) {
                grad_free(req);
                return 1;
        }
	*output = req;
	return 0;
}

int
snmp_req_cmp(void *ap, void *bp)
{
        SNMP_REQ *a = ap, *b = bp;
        return (a->addr.sin_addr.s_addr == b->addr.sin_addr.s_addr &&
		a->pdu->req_id == b->pdu->req_id) ? RCMP_EQ : RCMP_NE;
}

/* Free the SNMP request */
void
snmp_req_free(void *ptr)
{
        SNMP_REQ *req = ptr;
        snmp_pdu_free(req->pdu);
        grad_free(req->community);
        grad_free(req);
}

void
snmp_req_drop(int type, void *data, void *orig_data,
	      int fd, const char *status_str)
{
        SNMP_REQ *req = data ? data : orig_data;
        char ipbuf[GRAD_IPV4_STRING_LENGTH];

        grad_log(GRAD_LOG_NOTICE,
                 _("Dropping SNMP request from client %s: %s"),
                 grad_ip_iptostr(ntohl(req->addr.sin_addr.s_addr), ipbuf),
                 status_str);
}

static u_char send_buffer[RAD_BUFFER_SIZE];

int
snmp_req_respond(REQUEST *request)
{ 
	SNMP_REQ *req = request->data;
	struct snmp_session session;
        struct snmp_pdu *pdu;
        int len;

        pdu = snmp_agent_response(req->pdu, req->access);
        if (pdu) {
                session.version = SNMP_VERSION_1;
                session.community.str = req->community;
                session.community.len = strlen(req->community);
                len = sizeof(send_buffer);
                if (snmp_encode_request(&session, pdu, send_buffer, &len)==0) {
                        sendto(request->fd,
                               send_buffer, len,
                               0, (struct sockaddr *) &request->addr,
                               sizeof(request->addr));
                }
                snmp_pdu_free(pdu);
        }
        return 0;
}

#endif





