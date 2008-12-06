/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007,
   2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <grp.h>

#include <radius/mem.h>

LOCK_DECLARE(lock)

static struct group *
store_group(struct group *grp)
{
	int len;
	int i, grcnt;
	struct group *result;
	char *buffer;
	
	if (!grp)
		return NULL;
	
	for (grcnt = 0; grp->gr_mem[grcnt]; grcnt++)
		;

	len = sizeof(result[0]) +
		strlen(grp->gr_name) + 1 +
		strlen(grp->gr_passwd) + 1 +
		(grcnt + 1) * sizeof(grp->gr_mem[0]);

	for (i = 0; i < grcnt; i++)
		len += strlen(grp->gr_mem[i]) + 1;

	result = grad_emalloc(len);
	*result = *grp;
	result->gr_mem = (char**)(result + 1);
	buffer = (char*)(result->gr_mem + grcnt + 1);
	
#define COPY(m) do { \
	result-> m = buffer;\
	len = strlen(grp-> m) + 1;\
	buffer += len;\
	strcpy(result-> m, grp-> m); } while (0)

	COPY(gr_name);
	COPY(gr_passwd);
	for (i = 0; i < grcnt; i++) 
		COPY(gr_mem[i]);

	result->gr_mem[i] = NULL;
	return result;
}
	
struct group *
grad_getgrnam(const char *name)
{
	struct group *grp;

	LOCK_SET(lock);
	grp = store_group(getgrnam(name));
	LOCK_RELEASE(lock);
	return grp;
}
