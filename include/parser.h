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
struct pair_list {
	char *name;
	VALUE_PAIR *check;
	VALUE_PAIR *reply;
	int lineno;
	struct pair_list *next;
};
typedef struct pair_list PAIR_LIST;

extern char *source_filename;
extern int source_line_num;

extern PAIR_LIST *pair_result();
int init_parse(char *name, int complain);
int init_lex(char *name);
void auth_type_fixup(VALUE_PAIR *check);
void done_lex();
void users_sync();
