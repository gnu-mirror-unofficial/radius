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

int debug_level[6];

struct debug_module debug_module[6+1] = {

	"mem.c", 0,
	"leakdetect.c", 1,


	"checkrad.c", 2,
	"netfinger.c", 3,
	"compare.c", 4,
	"config.c", 5,

	(char*)0, 0
};

#endif
