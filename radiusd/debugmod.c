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

int debug_level[16];

struct debug_module debug_module[16+1] = {

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
       "stat.c", 12,
       "snmpserv.c", 13,
       "radutil.c", 14,
       "rewrite.y", 15,

	(char*)0, 0
};

#endif
