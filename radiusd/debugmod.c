/* This file is generated automatically.
 * Generator: ./scripts/debug.sh $Id$
 * Skeleton:  ./scripts/debugmod.m4
 */


/* $Id$ */
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#if RADIUS_DEBUG
#include <log.h>

int debug_level[19];

struct debug_module debug_module[19+1] = {

       "leakdetect.c", 0,
       "mem.c", 1,
       "mysql.c", 2,
       "postgres.c", 3,


       "radiusd.c", 4,
       "acct.c", 5,
       "auth.c", 6,
       "exec.c", 7,
       "files.c", 8,
       "sql.c", 9,
       "notify.c", 10,
       "pam.c", 11,
       "proxy.c", 12,
       "radius.c", 13,
       "ippool.c", 14,
       "stat.c", 15,
       "snmpserv.c", 16,
       "radutil.c", 17,
       "rewrite.y", 18,

	(char*)0, 0
};

#endif
