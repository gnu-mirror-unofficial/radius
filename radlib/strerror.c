/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

static char rcsid[] = 
"$Id$";

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if !defined(HAVE_STRERROR)

#include <stdio.h>
#include <stdlib.h>

#if defined(HAVE_SYS_ERRLIST)

extern char *sys_errlist[];
extern int sys_nerr;

char *
strerror(err)
	int err;
{
	static char buf[80];

	if (err > sys_nerr) {
		sprintf(buf, "error %d", err);
		return buf;
	}
	return sys_errlist[err];
}

#else

char *
strerror(err)
	int err;
{
	static char buf[80];

	sprintf(buf, "error %d", err);
	return buf;
}

#endif /* HAVE_SYS_ERRLIST */

#endif /* HAVE_STRERROR */

