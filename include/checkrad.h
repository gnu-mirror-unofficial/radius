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

typedef struct radck_arg RADCK_ARG;

struct radck_arg {
	RADCK_ARG    *next;
	char         *name;
	char         *value;
};

#define METHOD_FINGER 0
#define METHOD_SNMP   1 
#define METHOD_EXT    2

typedef struct radck_type RADCK_TYPE;

struct radck_type {
	RADCK_TYPE *next;
	char       *type;
	int        method;
	RADCK_ARG  *args;
};

RADCK_TYPE * find_radck_type(char *name);
