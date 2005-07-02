/* This file is part of GNU Radius.
   Copyright (C) 2003,2005 Free Software Foundation, Inc.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius/radius.h>
#include <rewrite.h>
#include <radiusd.h>
#include <radius/radscm.h>
#define RADIUS_SERVER_GUILE
#include <radsql.h>

#if defined(USE_SQL)

SCM_DEFINE(radius_sql_query, "radius-sql-query", 2, 0, 0,
           (SCM TYPE, SCM STRING),
"FIXME")
#define FUNC_NAME s_radius_sql_query
{
	SCM res;

        SCM_ASSERT(SCM_IMP(TYPE) && SCM_INUMP(TYPE),
                   TYPE, SCM_ARG1, FUNC_NAME);
	
	return sql_exec_query(SCM_INUM(TYPE), SCM_STRING_CHARS(STRING));
}
#undef FUNC_NAME

static grad_keyword_t kw[] = {
	{ "SQL_AUTH", SQL_AUTH },
	{ "SQL_ACCT", SQL_ACCT },
	{ NULL }
};

void
rscm_sql_init()
{
        int i;
        for (i = 0; kw[i].name; i++)
                scm_c_define(kw[i].name, SCM_MAKINUM(kw[i].tok));
#include <rscm_sql.x>
}

#endif	
