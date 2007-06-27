/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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

#ifndef _gnu_radius_radscm_h
#define _gnu_radius_radscm_h

SCM radscm_avl_to_list(grad_avp_t *pair);
grad_avp_t *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(grad_avp_t *pair);
grad_avp_t *radscm_cons_to_avp(SCM scm);
void radscm_init();

void rscm_syslog_init();
void rscm_utmp_init();
void rscm_avl_init();
void rscm_dict_init();
void rscm_radlog_init();
void rscm_rewrite_init();
void rscm_sql_init();
void rscm_add_load_path(char *path);
void rscm_server_init();
	
char *rscm_load_path(char *);

# define RAD_SCM_EVAL_X scm_primitive_eval_x
# define RAD_SCM_EVAL scm_primitive_eval
# define RAD_SCM_SYMBOL_VALUE(p) SCM_VARIABLE_REF(scm_c_lookup(p))

#endif /* !_gnu_radius_radscm_h */



