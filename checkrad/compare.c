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

#define RADIUS_MODULE 4
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <ctype.h>

#include <sysdep.h>
#include <mem.h>
#include <log.h>
#include <checkrad.h>

static int line_num = 0;       /* current input line number */
int want_header = 0;           /* line number where we expect to find header */
static HEADER_LIST *header_first; /* header definition */
static HEADER_LIST *header_last;  /* end of header definition */
static MATCH_LIST *match_first; /* match program */
static MATCH_LIST *match_last; /* last entry in the program */
static char buffer[1024];      /* temporary buffer */

static int parse_header(char *str);
static void fixup_prog(HEADER_LIST *hp);

int
add_match(match)
	MATCH_LIST *match;
{
	MATCH_LIST *mp;

	mp = emalloc(sizeof(*mp));
	mp->next = NULL;
	mp->type = match->type;
	mp->num = match->num;
	mp->hdr = estrdup(match->hdr);
	mp->value = checkrad_xlat(match->value);
	debug(5, ("mp->value: %s", mp->value));
	if (match_last)
		match_last->next = mp;
	else
		match_first = mp;
	match_last = mp;
}
		
void
add_header(str)
	char *str;
{
	HEADER_LIST *hp;

	hp = emalloc(sizeof *hp);
	hp->string = estrdup(str);
	if (header_last)
		header_last->next = hp;
	else
		header_first = hp;
	header_last = hp;
}




char *
select_offset(str, off)
	char *str;
	int off;
{
	int len = strlen(str);
	int size;
	char *p, *q;
	
	if (len <= off)
		return NULL;
	q = str + off;
	p = buffer;
	while (*q && !isspace(*q)) {
		if (p - buffer >= sizeof(buffer))
			break;
		*p++ = *q++;
	}
	*p = 0;
	return buffer;
}

#define isws(c) (((c)==' ')||((c)=='\t'))

char *
select_field(str, num)
	char *str;
	int num;
{
	char *q = str;
	while (--num) {
		/* Skip initial whitespace */
		while (*q && isws(*q))
			q++;
		/* Skip field itself */
		while (*q && !isws(*q))
			q++;
	}
	while (*q && isws(*q))
		q++;
	return select_offset(q, 0);
}

void
fixup_prog(hp)
	HEADER_LIST *hp;
{
	MATCH_LIST *p;

	for (p = match_first; p; p = p->next) 
		if (p->type == MATCH_OFFSET && p->hdr &&
		    strcmp(p->hdr, hp->string) == 0) {
			p->num = hp->offset;
			p->hdr = NULL;
		}
}

int
parse_header(str)
	char *str;
{
	char *p;
	char *q = str;
	int field = 0;
	int match = 0;
	HEADER_LIST *hp = header_first;
	
	while (*q && hp) {
		field++;
		/* Skip initial whitespace */
		while (*q && isspace(*q))
			q++;
		if (strncmp(q, hp->string, strlen(hp->string)) == 0) {
			hp->offset = q - str;
			q += strlen(hp->string);
			match++;
		} else
			return -1;
		hp = hp->next;
	}
	if (match == field) {
		MATCH_LIST *p;
		
		/* Fixup the program */
		for (hp = header_first; hp; hp = hp->next)
			fixup_prog(hp);
		/* Check the fixed program */
		for (p = match_first; p; p = p->next) 
			if (p->type == MATCH_OFFSET && p->hdr) {
				logit(L_ERR,
				      _("can't determine offset for field %s"),
				      p->hdr);
				return -1;
			}
		
		return 0;
	}
	return -1;
}

int
compare(str)
	char *str;
{
	int cnt;
	int match;
	MATCH_LIST *p;
	char *field_ptr;
	
	line_num++;

	debug(1,("compare: line %d: %s", line_num, str));
	
	/* Check if we need to analize output header */
	if (want_header && line_num == want_header) {
		want_header = 0;

		debug(1,("compare: parsing header"));
		return parse_header(str);
	}

	/* Ok, we have to check the line */
	cnt = match = 0;
	for (p = match_first; p; p = p->next) {
		cnt ++;
		switch (p->type) {
		case MATCH_FIELD:
			field_ptr = select_field(str, p->num);
			break;
		case MATCH_OFFSET:
			field_ptr = select_offset(str, p->num);
			break;
		}
		debug(2,("matching (%d) %s vs. %s",
			 p->type, field_ptr ? field_ptr : "(null)", p->value));
		if (field_ptr && strcmp(field_ptr, p->value) == 0)
			match++;
		else
			break;
	}
	debug(1, ("matched %d of %d", match, cnt));
	return cnt == match;
}
