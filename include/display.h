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
/* $Id$ */

#define MAX_COLS 80
#define HDRLINES 4

#define MT_delayed 0x01
#define MT_standout 0x02

extern char **screen;
extern char **headerbuf;

void update_display();
void writestr(int x, int y, char *str);
void alloc_screen(int nas_cnt, int port_cnt);
int readline(char *buffer, int size, int numeric);
void getint(char *str, int *retval);
void scroll(int);
void page(int);
void clearmsg();
int msg();
