/* This file is generated automatically.
 * Generator: /home/gray/radius/scripts/debug.sh $Id$
 * Skeleton:  /home/gray/radius/scripts/debugmod.m4
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

int debug_level[5];

struct debug_module debug_module[5+1] = {

    "leakdetect.c", 0,
    "mem.c", 1,
    "mysql.c", 2,
    "postgres.c", 3,
    "odbc.c", 4,



        (char*)0, 0
};

#endif
