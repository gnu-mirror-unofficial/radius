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

/* debug.c	Debugging module. */

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if RADIUS_DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <varargs.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radius.h>

int
set_module_debug_level(name, level)
	char *name;
	int   level;
{
	int  i;
	int  length;

	length = strlen(name);

	if (level == -1)
		level = MAX_DEBUG_LEVEL;

	for (i = 0; debug_module[i].name; i++) {
		if (strncmp(debug_module[i].name, name, length) == 0) {
			debug_level[ debug_module[i].modnum ] = level;
			return 0;
		}
	}
	return 1;
}

void
set_debug_levels(str)
	char *str;
{
	int  i;
	char *tok, *p, *save;
	int  length;
	int  level;

	for (tok = strtok_r(str, ",", &save); tok; 
             tok = strtok_r(NULL, ",", &save)) {
		p = strchr(tok, '=');
		if (p) {
			length = p - tok;
			level  = atoi(p+1);
		} else {
			length = strlen(tok);
			level  = MAX_DEBUG_LEVEL;
		}		
		for (i = 0; debug_module[i].name; i++) {
			if (strncmp(debug_module[i].name, tok, length) == 0) {
				debug_level[ debug_module[i].modnum ] = level;
				break;
			}
		}
	/*	if (debug_module[i].name == NULL)
			radlog(L_ERR, "unknown module: %s", tok); */
	}
}

void
clear_debug()
{
	int  i;

	for (i = 0; debug_module[i].name; i++) 
		debug_level[ debug_module[i].modnum ] = 0;
}

#else

#include <radius.h>

/*ARGSUSED*/
int
set_module_debug_level(name, level)
	char *name;
	int   level;
{
	radlog(L_ERR, _("compiled without debugging support"));
}

/*ARGSUSED*/
void
set_debug_levels(str)
	char *str;
{
	radlog(L_ERR, _("compiled without debugging support"));
}

#endif
