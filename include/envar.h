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

typedef struct envar_t envar_t;

struct envar_t {
	struct envar_t *next;
	char *name;
	char *value;
};

envar_t *envar_parse(char *str);
envar_t *envar_parse_argcv(int argc, char **argv);
void envar_free(envar_t *);
void envar_free_list(envar_t *);
char *envar_lookup(envar_t *, char *);
envar_t *envar_dup(envar_t *env);
envar_t *envar_merge_lists(envar_t *prim, envar_t *sec);

