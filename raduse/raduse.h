#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sysdep.h>
#include <radius.h>
#include <radpaths.h>
#include <radutmp.h>
#include <radlast.h>
#include <log.h>

#include <asn1.h>
#include <snmp.h>
#include <radsnmp.h>
#include <radmibs.h>

#ifndef offsetof
# define offsetof(s,m) (off_t)(&((s*)0)->m)
#endif

typedef int (*sess_handler_t)(struct snmp_var *, void*);

typedef struct {
	oid_t oid;
	void *closure;
} SNMP_GET_TAB;

typedef struct {
	oid_t oid;
	off_t offset;
} SNMP_WALK_TAB;

struct nas_usage {
	struct nas_usage *next;
	UINT4 ipaddr;
	char *ident;
	counter ports_active;
	counter ports_idle;
	Auth_server_stat auth;
	Acct_server_stat acct;
};

extern char *hostname;
extern char *community;
extern int port;

char *stat_ident;
serv_stat stat_config_reset;
counter stat_total_lines;
counter stat_lines_in_use;
counter stat_lines_idle;
