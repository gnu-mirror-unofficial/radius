/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

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
                char *string;
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
extern u_char messg_id;
extern int reply_code;
extern VALUE_PAIR *reply_list;
extern int verbose;
extern int abort_on_failure;
extern int x_argmax;
extern int x_argc;
extern char **x_argv;

int open_input(char *name);
void close_input();
void set_yydebug();
void parse_error __PVAR((const char *fmt, ...));
void print(Variable *var);
void radtest_send(int port, int code, Variable *var, Symtab *cntl);
void putback(char *str);
void prompt();
void tempvar_free(Variable *var);
int var_free(Variable *var);
void var_print(Variable *var);
int compare_lists(VALUE_PAIR *reply, VALUE_PAIR *sample);
int parse_datum(char *p, union datum *dp);

