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

/* debug.c	Debugging module. */

static char rcsid[] = 
"$Id$";

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
#include <radiusd.h>

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

int
set_debug_levels(str)
	char *str;
{
	int  i;
	char *tok, *p;
	int  length;
	int  level;

	for (tok = strtok(str, ","); tok; tok = strtok(NULL, ",")) {
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

int
clear_debug()
{
	int  i;

	for (i = 0; debug_module[i].name; i++) 
		debug_level[ debug_module[i].modnum ] = 0;
}

int
debug_output(module, line, function, msg)
	char *module;
	int  line;
	char *function;
	char *msg;
{
	if (function)
		radlog(L_DBG, "%s:%d:%s:%s", module, line, function, msg);
	else
		radlog(L_DBG, "%s:%d:%s", module, line, msg);
}	

char *
debug_sprintf(msg, va_alist)
	char *msg;
	va_dcl
{
	va_list ap;
	static char debug_buffer[RADIUS_DEBUG_BUFFER_SIZE];

	va_start(ap);
	vsnprintf(debug_buffer, sizeof(debug_buffer), msg, ap);
	va_end(ap);
	return debug_buffer;
}

#else

#include <radiusd.h>

/*ARGSUSED*/
int
set_module_debug_level(name, level)
	char *name;
	int   level;
{
	radlog(L_ERR, _("compiled without debugging support"));
}

/*ARGSUSED*/
int
set_debug_levels(str)
	char *str;
{
	radlog(L_ERR, _("compiled without debugging support"));
}

#endif
