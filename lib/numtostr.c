/* This file is part of GNU Radius.
   Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008 Free Software Foundation
  
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
#include <unistd.h>
#include <string.h>
#include "intprops.h"

size_t
numtostr (inttype i, char *buf, size_t size)
{
	char ibuf[INT_STRLEN_BOUND (inttype)];
	char *p = ibuf + sizeof ibuf;
	size_t s;
	
	if (i < 0) {
		do
			*--p = '0' - i % 10;
		while ((i /= 10) != 0);

		*--p = '-';
	} else {
		do
			*--p = '0' + i % 10;
		while ((i /= 10) != 0);
	}

	s = ibuf + sizeof ibuf - p;
	if (!buf || size == 0)
		return s;
	
	size--;
	if (size < s) 
		s = size;

	memcpy(buf, p, s);
	buf[s] = 0;
	
	return s;
}
