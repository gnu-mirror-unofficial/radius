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

#define _(s) s
static char rcsid[] = 
"$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <varargs.h>
#include <ctype.h>
#include <log.h>
#include <mem.h>
#include "display.h"
#include "screen.h"


int initialized = 0;

char **headerbuf; /* screen header */
char **screen;    /* screen contents */
int total_lines;  /* maximum number of lines in `screen' */
int screen_lines; /* number of lines actually filled in */
int top_row;      /* number of topmost row */
int max_row;      /* number of last displayable row + 1 */

char msgtext[128];
int msglen = 0; /* length of the message string lastly output to the screen */
int msg_row = HDRLINES;

void firstpage();
void lastpage();

void
alloc_screen(nas_cnt, port_cnt)
	int nas_cnt;
	int port_cnt;
{
	int i;
	int size;
	char *ptr;
	
	total_lines = nas_cnt * port_cnt * 3;
	size = total_lines * ( sizeof(char*) + screen_width );

	screen = emalloc( size );
	
	ptr = (char*) (screen + total_lines);
	for (i = 0; i < total_lines; i++, ptr += screen_width) {
		screen[i] = ptr;
		ptr[0] = 0;
	}

	/* header */
	headerbuf = emalloc( HDRLINES * ( sizeof(char*) + screen_width ));
	
	ptr = (char*) (headerbuf + HDRLINES);
	for (i = 0; i < HDRLINES; i++, ptr += screen_width) {
		headerbuf[i] = ptr;
		ptr[0] = 0;
	}
}

void
i_display()
{
	int n;
	
	for (n = 0; n < HDRLINES; n++)
		printf("%-*.*s\n",
		       screen_width, screen_width,
		       headerbuf[n]);
	printf("\n");
	for (n = 0; n < max_row; n++) 
		printf("%-*.*s\n",
		       screen_width, screen_width,
		       screen[ top_row + n ]) ;
}

void
u_display()
{
	Move_to(0, 0);
	i_display();
}

void
update_display(nrows)
	int nrows;
{
	int n = screen_length - HDRLINES - 2;
	
	screen_lines = nrows;
	if (screen_lines - top_row > n)
		max_row = n;
	else
		max_row = screen_lines - top_row;

	if (!smart_terminal)
		i_display();
	else if (!initialized) {
		initialized = 1;
		clear();
		i_display();
	} else
		u_display();
}

void
writestr(x, y, str)
	int x;
	int y;
	char *str;
{
	Move_to(x, y);
	printf("%-*.*s",
	       screen_width, screen_width,
	       str);
}


/*VARARGS2*/
msg(type, msgfmt, va_alist)
	int             type;
        char           *msgfmt;
	va_dcl
{
	register int    i;
	va_list ap;
	char next_msg[128];
	
	va_start(ap);

	next_msg[0] = ' ';
	i = 1 + vsprintf(next_msg+1, msgfmt, ap);
	
	if (!overstrike) {
		if ((type & MT_delayed) == 0) {
			Move_to(0, msg_row);
			type & MT_standout ?
				standout(next_msg) :
				fputs(next_msg, stdout);
			if (msglen > i)
				clear_eol(msglen - i);
			msglen = i;
		}
	} 
}

void
clearmsg()
{
	Move_to(0, msg_row);
	clear_eol(screen_width);
}

void
scroll(amount)
	int amount;
{
	top_row += amount;
	if (top_row < 0)
		top_row = 0;
	else if (top_row > 2 + screen_lines - (screen_length - msg_row)) {
		putchar('\a');
		top_row = 2 + screen_lines - (screen_length - msg_row);
	}
}

void
page(amount)
	int amount;
{
	scroll(amount*(screen_length - msg_row));
}

void
firstpage()
{
	top_row = 0;
}

void
lastpage()
{
	top_row = 2 + screen_lines - (screen_length - msg_row);
}	

void
getint(str, retval)
	char *str;
	int *retval;
{
	char buf[64];
	int n;
	
	msg(MT_standout, str);
	if ((n = readline(buf, sizeof(buf), 1)) > 0)
		*retval = n;
	clearmsg();
}

int
readline(buffer, size, numeric)
	char           *buffer;
	int             size;
	int             numeric;
{
	register char  *ptr = buffer;
	register char   ch;
	register char   cnt = 0;
	register char   maxcnt = 0;

	/* allow room for null terminator */
	size -= 1;

	/* read loop */
	while ((fflush(stdout), read(0, ptr, 1) > 0)) {
		/* newline means we are done */
		if ((ch = *ptr) == '\n') {
			break;
		}
		/* handle special editing characters */
		if (ch == ch_kill) {
			/* kill line -- account for overstriking */
			if (overstrike) {
				msglen += maxcnt;
			}
			/* return null string */
			*buffer = '\0';
			putchar('\r');
			return -1;
		} else if (ch == ch_erase) {
			/* erase previous character */
			if (cnt <= 0) {
				/* none to erase! */
				putchar('\7');
			} else {
				fputs("\b \b", stdout);
				ptr--;
				cnt--;
			}
		}
		/* check for character validity and buffer overflow */
		else if (cnt == size || (numeric && !isdigit(ch)) ||
			 !isprint(ch)) {
			/* not legal */
			putchar('\7');
		} else {
			/* echo it and store it in the buffer */
			putchar(ch);
			ptr++;
			cnt++;
			if (cnt > maxcnt) {
				maxcnt = cnt;
			}
		}
	}

	/* all done -- null terminate the string */
	*ptr = '\0';

	/* account for the extra characters in the message area */
	/* (if terminal overstrikes, remember the furthest they went) */
	msglen += overstrike ? maxcnt : cnt;

	/* return either inputted number or string length */
	putchar('\r');
	return cnt == 0 ? -1 : numeric ? atoi(buffer) : cnt;
}
