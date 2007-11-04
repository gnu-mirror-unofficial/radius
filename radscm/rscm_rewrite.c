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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius/radius.h>
#define RADIUS_SERVER_GUILE
#include <rewrite.h>
#include <radius/radscm.h>

SCM_DEFINE(rad_rewrite_execute_string, "rad-rewrite-execute-string", 1, 0, 0,
           (SCM STRING),
"Interpret STRING as an invocation of a function in Rewrite language and\n"
"execute it.\n"
"Return value: return of the corresponding Rewrite call, translated to\n"
"the Scheme data type.\n")         
#define FUNC_NAME s_rad_rewrite_execute_string
{
	grad_value_t val;
	SCM retval;
	
        SCM_ASSERT(scm_is_string(STRING), STRING, SCM_ARG1, FUNC_NAME);
        if (rewrite_interpret(scm_i_string_chars(STRING), NULL, &val)) {
                scm_misc_error(FUNC_NAME,
                               "Error parsing expression: ~S",
                               scm_list_1(STRING));
        }

        retval = radscm_datum_to_scm(&val);
	grad_value_free(&val);
	return retval;
}
#undef FUNC_NAME

SCM_DEFINE(rad_rewrite_execute, "rad-rewrite-execute", 1, 0, 0,
           (SCM ARGLIST),
"Execute a Rewrite language function.\n"
"(car ARGLIST) is interpreted as a name of the Rewrite function to execute,\n"
"and (cdr ARGLIST) as a list of arguments to be passed to it.\n"
"Return value: return of the corresponding Rewrite call, translated to\n"
"the Scheme data type.\n")         
#define FUNC_NAME s_rad_rewrite_execute
{
        SCM_ASSERT((SCM_IMP(ARGLIST) && ARGLIST == SCM_EOL)
                   || (SCM_NIMP(ARGLIST) && SCM_CONSP(ARGLIST)),
                   ARGLIST, SCM_ARG2, FUNC_NAME);
        
        return radscm_rewrite_execute(FUNC_NAME, ARGLIST);
}
#undef FUNC_NAME

void
rscm_rewrite_init()
{
#include <rscm_rewrite.x>
}

void
rscm_server_init()
{
	rscm_radlog_init();
	rscm_rewrite_init();
#if defined(USE_SQL)
	rscm_sql_init();
#endif
}
