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

#include <symtab.h>

#define MAX_DEBUG_MODE 10
#define dbg(m,l) if (debug_level[m] >= l) debug_printf
extern int debug_level[];

#define MAX_STRING 128

enum {
	Undefined,
	Builtin,
	Integer,
	Ipaddress,
	String,
	Vector
};

typedef struct variable Variable;
struct variable {
	Symbol *next;
	char *name;
	int type;
	union datum {
		int number;
		char string[MAX_STRING];
		VALUE_PAIR *vector;
		UINT4 ipaddr;
		DICT_VALUE *dval;
		struct {
			int (*set)();
			int (*print)();
		} builtin;
	} datum;
};

extern Symtab *vartab;
extern UINT4 auth_server;
extern int   auth_port;
extern UINT4 acct_server;
extern int   acct_port;
extern long  timeout;
extern int nretries;
extern u_char messg_id;
extern int reply_code;
extern int verbose;

int open_input(char *name);
void close_input();
void set_yydebug();
void parse_error();
void print(Variable *var);
void radtest_send(int port, int code, Variable *var);
void putback(char *str);


