/* This file is part of GNU Radius.
   Copyright (C) 2007 Free Software Foundation, Inc.

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
#include <unistd.h>

static char c_coltab[] = {
	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
	' ', '!', '"', '#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
	'`', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '{', '|', '}', '~'
};

#define c_colsiz (sizeof(c_coltab) / sizeof(c_coltab[0]))

int
grad_c_strcasecmp(const char *a, const char *b)
{
	int d = 0;
	for (; d == 0; a++, b++) {
		unsigned ac = *(unsigned char*) a;
		unsigned bc = *(unsigned char*) b;
		if (ac == 0 || bc == 0) 
			return ac - bc;
		if (ac > c_colsiz || bc > c_colsiz)
			d = ac - bc;
		d = c_coltab[ac] - c_coltab[bc];
	}
	return d;
}
			
int
grad_c_strncasecmp(const char *a, const char *b, size_t n)
{
	int d = 0;
	for (; d == 0 && n > 0; a++, b++, n--) {
		unsigned ac = *(unsigned char*) a;
		unsigned bc = *(unsigned char*) b;
		if (ac == 0 || bc == 0)
			return ac - bc;
		if (ac > c_colsiz || bc > c_colsiz)
			d = ac - bc;
		d = c_coltab[ac] - c_coltab[bc];
	}
	return d;
}
			
