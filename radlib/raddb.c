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
#include <obstack1.h>

struct raddb_file {
	FILE *input;
	int  line;
	char *filename;
	char *token;
	int toklen;
	struct obstack tokstk;
};

#define isws(c) ((c) == ' ' || (c) == '\t')

static int nextkn(struct raddb_file *file);
static void skip_to_eol(FILE *input);

int
nextkn(file)
	struct raddb_file *file;
{
	int    c;
	static char tokbuf[2];
	
	while ((c = getc(file->input)) != EOF && isws(c))
		;
	if (c == EOF)
		return 0;
	file->toklen = 0;

	if (c == '\n' || c == '#') {
		file->token = tokbuf;
		file->token[0] = c;
		file->token[1] = 0;
		return c;
	}
	
	do {
		obstack_1grow(&file->tokstk, c);
		file->toklen++;
	} while ((c = getc(file->input)) != EOF && !isspace(c));
	if (c != EOF)
		ungetc(c, file->input);

	obstack_1grow(&file->tokstk, 0);
	file->token = obstack_finish(&file->tokstk);
	return 1;
}

void
skip_to_eol(input)
	FILE *input;
{
	int c;

	while ((c = getc(input)) != EOF) {
		if (c == '\n') {
			ungetc(c, input);
			return;
		}
	}
}

int
read_raddb_file(name, vital, fcnt, fun, closure)
	char *name;   /* file name */
	int vital;    /* is the file vital */
	int fcnt;
	int (*fun)(); /* handler */
	void *closure;
{
	int    nf;
	char **fv;
	struct raddb_file file;
	
	file.input = fopen(name, "r");
	if (!file.input) {
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
	file.filename = name;
	file.line = 1;
	
	fv = emalloc(fcnt * sizeof(fv[0]));
	nf = 0;
	obstack_init(&file.tokstk);
	
	while (nextkn(&file)) {

		if (file.token[0] == '\n') {
			if (nf) {
				fun(closure, nf, fv,
				    file.filename, file.line);
				obstack_free(&file.tokstk, fv[0]);
				while (nf > 0)
					fv[--nf] = NULL;
			}
			file.line++;
			continue;
		}
			
		if (file.token[0] == '#') {
			skip_to_eol(file.input);
			continue;
		}

		if (nf < fcnt) {
			fv[nf++] = file.token;
		} else {
			radlog(L_NOTICE, _("%s:%d: excess fields ignored"),
			       file.filename, file.line);
			skip_to_eol(file.input);
		}
	}			

	if (nf) {
		fun(closure, nf, fv, file.filename, file.line);
	}

	efree(fv);
	obstack_free(&file.tokstk, NULL);
	fclose(file.input);

	return 0;
}
