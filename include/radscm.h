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

SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);
void radscm_init();

void rscm_syslog_init();
void rscm_utmp_init();
void rscm_avl_init();
void rscm_dict_init();
void rscm_radlog_init();
void rscm_rewrite_init();
void rscm_add_load_path(char *path);
	
char *rscm_load_path(char *);

#if GUILE_VERSION == 14

# define SCM_STRING_CHARS SCM_CHARS
# define scm_list_1 SCM_LIST1
# define scm_list_2 SCM_LIST2
# define scm_list_3 SCM_LIST3
# define scm_list_4 SCM_LIST4
# define scm_list_5 SCM_LIST5
# define scm_list_n SCM_LISTN

# define scm_c_define scm_sysintern

# define scm_primitive_eval_x scm_eval_x

# define RAD_SCM_SYMBOL_VALUE(p) scm_symbol_value0(p)

# define scm_i_big2dbl scm_big2dbl

extern SCM scm_long2num (long val);

#elif GUILE_VERSION >= 16

# define RAD_SCM_SYMBOL_VALUE(p) SCM_VARIABLE_REF(scm_c_lookup(p))
# define rad_scm_cell scm_cell

#endif



