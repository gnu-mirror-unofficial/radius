/* This file is part of GNU Radius.
   Copyright (C) 2003, 2005, 2007, 2010, 2013 Free Software Foundation, Inc.

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
#include <rewrite.h>
#define RADIUS_SERVER_GUILE
#include <radiusd.h>
#include <radius/radscm.h>
#include <radsql.h>

#if defined(USE_SQL)

SCM_DEFINE_PUBLIC(radius_sql_query, "radius-sql-query", 2, 0, 0,
		  (SCM type, SCM string),
"Sends the query @var{string} to the SQL server identified by @var{type} "
"and returns a list of the reply tuples.  Allowed values for @var{type} "
"are: @samp{SQL-AUTH} for authentication database and @samp{SQL-ACCT}, for "
"accounting database.  The @var{string} must be a @samp{SELECT}-like query.\n")
#define FUNC_NAME s_radius_sql_query
{
	SCM result;
	char *query;
	
        SCM_ASSERT(scm_is_integer(type), type, SCM_ARG1, FUNC_NAME);
	query = scm_to_locale_string(string);
	result = sql_exec_query(scm_to_int(type), query);
	free(query);
	return result;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(radius_sql_run_query, "radius-sql-run-query", 2, 0, 0,
		  (SCM type, SCM string),
"Sends the query @var{string} to the SQL server identified by @var{type} "
"and returns number of affected rows.  Allowed values for @var{type} "
"are: @samp{SQL-AUTH} for authentication database and @samp{SQL-ACCT}, for "
"accounting database.  The @var{string} must be a @samp{INSERT}-like "
"query.\n")
#define FUNC_NAME s_radius_sql_run_query
{
	SCM result;
	char *query;

        SCM_ASSERT(scm_is_integer(type), type, SCM_ARG1, FUNC_NAME);
	query = scm_to_locale_string(string);
	result = sql_run_query(scm_to_int(type), query);
	free(query);
	return result;
}
#undef FUNC_NAME

static grad_keyword_t kw[] = {
	{ "SQL_AUTH", SQL_AUTH },
	{ "SQL-AUTH", SQL_AUTH },
	{ "SQL_ACCT", SQL_ACCT },
	{ "SQL-ACCT", SQL_ACCT },
	{ NULL }
};

void
rscm_sql_init()
{
        int i;
        for (i = 0; kw[i].name; i++) {
                scm_c_define(kw[i].name, scm_from_int(kw[i].tok));
		scm_c_export(kw[i].name, NULL);
	}
#include <rscm_sql.x>
}

#endif	
