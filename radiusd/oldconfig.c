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
#include <radiusd.h>

static FILE *infile;
static int line;
static char *filename;
static char token[256];
static int toklen;

#define isws(c) ((c) == ' ' || (c) == '\t')

static int
nextkn()
{
	int c;
	char *p;
	
	while ((c = getc(infile)) != EOF && isws(c))
		;
	if (c == EOF)
		return 0;
	p = token;
	toklen = 0;

	if (c == '\n' || c == '#') {
		token[0] = c;
		token[1] = 0;
		return c;
	}
	
	do {
		if (p >= token + sizeof(token)) {
			radlog(L_ERR, _("%s:%d: token too long"),
			    filename, line);
			break;
		}
		*p++ = c;
		toklen++;
	} while ((c = getc(infile)) != EOF && !isspace(c));
	if (c != EOF)
		ungetc(c, infile);
	*p = 0;
	return 1;
}

void
skip_to_eol()
{
	int c;

	while ((c = getc(infile)) != EOF) {
		if (c == '\n') {
			ungetc(c, infile);
			return;
		}
	}
}

int
read_old_config_file(name, vital, fcnt, flen, fv, fun, closure)
	char *name;   /* file name */
	int vital;    /* is the file vital */
	int fcnt;     /* number of fields */
	int *flen;    /* array of field length */
	char **fv;    /* array of field pointers */
	int (*fun)(); /* handler */
	void *closure;
{
	int nf;
	
	infile = fopen(name, "r");
	if (!infile) {
		if (vital) {
			radlog(L_ERR|L_PERROR, _("can't open file `%s'"),
			    name);
			return -1;
		} else {
			radlog(L_NOTICE|L_PERROR, _("can't open file `%s'"),
			    name);
			return 0;
		}
	}
	filename = name;
	line = 1;
	
	nf = 0;
	while (nextkn()) {

		if (token[0] == '\n') {
			if (nf) {
				fun(closure, nf, fv, filename, line);
				nf = 0;
			}
			line++;
			continue;
		}
			
		if (token[0] == '#') {
			skip_to_eol();
			continue;
		}

		if (nf < fcnt) {
			strncpy(fv[nf], token, flen[nf]);
			fv[nf][flen[nf]-1] = 0;
			if (flen[nf] < toklen)
				radlog(L_WARN, _("%s:%d: field %d too long"),
				    name, line, nf);
			nf++;
		} else {
			radlog(L_NOTICE, _("%s:%d: excess fields ignored"),
			    name, line);
			skip_to_eol();
		}
	}			

	if (nf) {
		fun(closure, nf, fv, filename, line);
		nf = 0;
	}

	fclose(infile);

	return 0;
}
