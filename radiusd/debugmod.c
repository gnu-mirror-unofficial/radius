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

int debug_level[17];

struct debug_module debug_module[17+1] = {

       "leakdetect.c", 0,
       "mem.c", 1,


       "radiusd.c", 2,
       "acct.c", 3,
       "auth.c", 4,
       "exec.c", 5,
       "files.c", 6,
       "sql.c", 7,
       "notify.c", 8,
       "pam.c", 9,
       "proxy.c", 10,
       "radius.c", 11,
       "ippool.c", 12,
       "stat.c", 13,
       "snmpserv.c", 14,
       "radutil.c", 15,
       "rewrite.y", 16,

	(char*)0, 0
};

#endif
