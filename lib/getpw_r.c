/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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
#include <pwd.h>

LOCK_DECLARE(lock)

static int
store_passwd(struct passwd *pwd, struct passwd *result, char *buffer,
	     int buflen)
{
	int len;

	*result = *pwd;

#define COPY(m) \
	result->m = buffer;\
	len = strlen(pwd->m) + 1;\
	if (len	> buflen) return -1;\
	buflen -= len;\
	buffer += len;\
	strcpy(result->m, pwd->m)

	COPY(pw_name);
	COPY(pw_passwd);
	COPY(pw_gecos);
	COPY(pw_dir);
	COPY(pw_shell);
	return 0;
}

/* struct passwd *getpwnam_r(const char  *name,
              struct passwd *pwd, char *buffer, int buflen);
 */
struct passwd *
grad_getpwnam_r(const char  *name, struct passwd *result, char *buffer,
	       int buflen)
{
	struct passwd *pwd;
	LOCK_SET(lock);
	pwd = getpwnam(name);
	if (!pwd || store_passwd(pwd, result, buffer, buflen))
		result = NULL;
	LOCK_RELEASE(lock);
	return result;
}



