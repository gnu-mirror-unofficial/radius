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

#include <symtab.h>

struct matching_rule {
	struct matching_rule *next;
	char *name;
	VALUE_PAIR *lhs;
	VALUE_PAIR *rhs;
	int lineno;
};
typedef struct matching_rule MATCHING_RULE;

extern char *source_filename;
extern int source_line_num;

extern Symtab *user_tab;
extern MATCHING_RULE *hints;

extern MATCHING_RULE *pair_result();
int init_parse(char *name, int complain);
int init_lex(char *name);
void done_lex();
void users_sync();
