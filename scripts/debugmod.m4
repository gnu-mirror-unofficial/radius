divert
/* $Id$ */
/* This file is part of GNU Radius.
 * Copyright (C) 2001, Sergey Poznyakoff
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * GNU Radius is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#if RADIUS_DEBUG
#include <radius.h>

int debug_level[MODNUM];

struct debug_module debug_module[MODNUM+1] = {
undivert(1)
undivert(2)
	(char*)0, 0
};

#endif
