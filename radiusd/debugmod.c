/* This file is generated automatically.
 * Generator: ./scripts/debug.sh $Id$
 * Skeleton:  ./scripts/debugmod.m4
 */


/* $Id$ */
/* This file is part of GNU RADIUS.
 * Copyright (C) 2001, Sergey Poznyakoff
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
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
       "stat.c", 14,
       "snmpserv.c", 15,
       "radutil.c", 16,
       "rewrite.y", 17,
       "checkrad.c", 18,

	(char*)0, 0
};

#endif
