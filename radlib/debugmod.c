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

int debug_level[2];

struct debug_module debug_module[2+1] = {

	"mem.c", 0,
	"leakdetect.c", 1,



	(char*)0, 0
};

#endif
