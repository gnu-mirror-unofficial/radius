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

int debug_level[3];

struct debug_module debug_module[3+1] = {

	"mem.c", 0,
	"leakdetect.c", 1,


	"gram.y", 2,

	(char*)0, 0
};

#endif
