/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <radius.h>

/*FIXME: fcnt is unused */
int
read_raddb_file(filename, vital, fcnt, fun, closure)
	char *filename;   /* file name */
	int vital;    /* is the file vital */
	int fcnt;
	int (*fun)(); /* handler */
	void *closure;
{
	int    argc;
	char **argv;
	FILE *input;
	int  line = 1;
	char *lineptr = NULL;
	size_t bsize = 0;
	int nread;
	
	input = fopen(filename, "r");
	if (!input) {
		if (vital) {
			radlog(L_ERR|L_PERROR, _("can't open file `%s'"),
			       filename);
			return -1;
		} else {
			radlog(L_NOTICE|L_PERROR, _("can't open file `%s'"),
			       filename);
			return 0;
		}
	}

	while (getline(&lineptr, &bsize, input) > 0) {
		nread = strlen(lineptr);
		if (nread == 0)
			break;
		if (lineptr[nread-1] == '\n')
			lineptr[nread-1] = 0;
		if (lineptr[0] == 0)
			continue;
		if (argcv_get(lineptr, "", &argc, &argv) == 0) {
			int n;
			for (n = 0; n < argc && argv[n][0] != '#'; n++)
				;
			if (n)
				fun(closure, n, argv, filename, line);
		}
		line++;
		if (argv)
			argcv_free(argc, argv);
	}

	if (lineptr)
		free(lineptr);
	fclose(input);

	return 0;
}
