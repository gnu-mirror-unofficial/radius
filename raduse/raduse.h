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

typedef int (*sess_handler_t)(struct snmp_var *, void*);

struct mib_data {
	oid_t oid;
	void *closure;
};

extern char *hostname;
extern char *community;
extern int port;

char *stat_ident;
serv_stat stat_config_reset;
counter stat_total_lines;
counter stat_lines_in_use;
counter stat_lines_idle;
