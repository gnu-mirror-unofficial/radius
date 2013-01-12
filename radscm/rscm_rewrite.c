/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2005, 2007, 2010, 2013 Free Software
   Foundation, Inc.

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
   along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius/radius.h>
#define RADIUS_SERVER_GUILE
#include <rewrite.h>
#include <radius/radscm.h>

SCM_DEFINE_PUBLIC(rad_rewrite_execute_string, "rad-rewrite-execute-string",
		  1, 0, 0,
		  (SCM string),
"Interprets @var{string} as a function call in Rewrite language and"
"executes it.\n\n"
"Return value: return of the corresponding Rewrite call, translated to "
"a corresponding Scheme data type.\n")         
#define FUNC_NAME s_rad_rewrite_execute_string
{
	grad_value_t val;
	SCM retval;
	char *str;
	int rc;
	
        SCM_ASSERT(scm_is_string(string), string, SCM_ARG1, FUNC_NAME);
	str = scm_to_locale_string(string);
	rc = rewrite_interpret(str, NULL, &val);
	free(str);
        if (rc) {
                scm_misc_error(FUNC_NAME,
                               "Error parsing expression: ~S",
                               scm_list_1(string));
        }

        retval = radscm_datum_to_scm(&val);
	grad_value_free(&val);
	return retval;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_rewrite_execute, "rad-rewrite-execute", 1, 0, 0,
		  (SCM arglist),
"Executes a Rewrite language function.\n"
"@code{(car @var{arglist})} is interpreted as a name of function to run, "
"and @code{(cdr @var{arglist}) as a list of arguments to be passed to it.\n\n"
"Return value: return of the corresponding Rewrite call, translated to\n"
"a corresponding Scheme data type.\n")         
#define FUNC_NAME s_rad_rewrite_execute
{
        SCM_ASSERT(scm_is_null(arglist) || scm_is_pair(arglist),
                   arglist, SCM_ARG1, FUNC_NAME);
        
        return radscm_rewrite_execute(FUNC_NAME, arglist);
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
