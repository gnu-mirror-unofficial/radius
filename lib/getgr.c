/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <grp.h>
#include <mem.h>

LOCK_DECLARE(lock)

struct group *
store_group(grp)
	struct group *grp;
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

	result = emalloc(len);
	*result = *grp;
	result->gr_mem = (char**)(result + 1);
	buffer = (char*)(result->gr_mem + grcnt + 1);
	
#define COPY(m) do { \
	result->##m = buffer;\
	len = strlen(grp->##m) + 1;\
	buffer += len;\
	strcpy(result->##m, grp->##m); } while (0)

	COPY(gr_name);
	COPY(gr_passwd);
	for (i = 0; i < grcnt; i++) 
		COPY(gr_mem[i]);

	result->gr_mem[i] = NULL;
	return result;
}
	
struct group *
rad_getgrnam(name)
	const char *name;
{
	struct group *grp;

	LOCK_SET(lock);
	grp = store_group(getgrnam(name));
	LOCK_RELEASE(lock);
	return grp;
}
