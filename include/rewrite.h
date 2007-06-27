/* This file is part of GNU Radius.

   Copyright (C) 2000,2001,2002,2003,2005,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */
/*
 * Data types
 */
typedef enum grad_data_type {
        Undefined,          /* Undefined type */
        Integer,            /* 32-bit integer, signed or unsigned */ 
        String,             /* Nul-terminated ASCII (in future: UTF-8)
			       string or character array */
#define Max_datatype String+1    
} grad_data_type_t;

typedef struct grad_value {
	grad_data_type_t type;
	union grad_datum datum;
} grad_value_t;

void rewrite_init();
int rewrite_interpret(char *expr, grad_request_t *req, grad_value_t *val);
int rewrite_eval(char *func, grad_request_t *req, grad_value_t *val);
char *rewrite_compile(char *expr);
int rewrite_stmt_term(int finish, void *block_data, void *handler_data);
size_t rewrite_get_stack_size();
void rewrite_set_stack_size(size_t s);
int rewrite_invoke(grad_data_type_t rettype, grad_value_t *val,
		   const char *name,
		   grad_request_t *request, char *typestr, ...);
void grad_value_free(grad_value_t *val);

#ifdef RADIUS_SERVER_GUILE
SCM radscm_datum_to_scm(grad_value_t *val);
int radscm_scm_to_ival(SCM cell, int *val);
SCM radscm_rewrite_execute(const char *func_name, SCM ARGS);
#endif
