/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2004, 2007, 2008, 2010 Free
   Software Foundation, Inc.

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
#include <radius/radscm.h>

static grad_keyword_t radlog_kw[] = {
#define D(c) { #c, c }
        /* log categories */
        D(GRAD_LOG_MAIN),
        D(GRAD_LOG_AUTH),
        D(GRAD_LOG_ACCT),
        D(GRAD_LOG_PROXY),
        D(GRAD_LOG_SNMP),
        /* log priorities */
        D(GRAD_LOG_EMERG),
        D(GRAD_LOG_ALERT),
        D(GRAD_LOG_CRIT),
        D(GRAD_LOG_ERR),
        D(GRAD_LOG_WARN),
        D(GRAD_LOG_NOTICE),
        D(GRAD_LOG_INFO),
        D(GRAD_LOG_DEBUG),
        { NULL }
#undef D
};

static int
parse_facility(SCM list)
{
        int accval = 0;
        for (; !scm_is_null(list); list = SCM_CDR(list)) {
                SCM car = SCM_CAR(list);
                int val = 0;
                
                if (scm_is_integer(car)) 
                        val = scm_to_int(car);
                else if (scm_is_string(car)) {
			char *s = scm_to_locale_string(car);
                        val = grad_xlat_keyword(radlog_kw, s, 0);
			free(s);
		} else
                        continue; /* FIXME: warning message? */
                accval |= val;
        } 
        return accval;
}

SCM_DEFINE(rad_log_open, "rad-log-open", 1, 0, 0,
           (SCM PRIO),
"Open radius logging to the severity level PRIO.")         
#define FUNC_NAME s_rad_log_open
{
        int prio;

        if (scm_is_integer(PRIO)) {
                prio = scm_to_int(PRIO);
        } else {
                SCM_ASSERT(scm_is_pair(PRIO), PRIO, SCM_ARG1, FUNC_NAME);
                prio = parse_facility(PRIO);
        }

        log_open(prio);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_log, "rad-log", 2, 0, 0,
           (SCM PRIO, SCM TEXT),
"Output TEXT to the radius logging channel corresponding to\n"
"category/severity given by PRIO.\n")
#define FUNC_NAME s_rad_log
{
        int prio;
	char *s;
	
        if (PRIO == SCM_BOOL_F) {
                prio = GRAD_LOG_INFO;
        } else if (scm_is_integer(PRIO)) {
                prio = scm_to_int(PRIO);
        } else {
                SCM_ASSERT(scm_is_pair(PRIO), PRIO, SCM_ARG1, FUNC_NAME);
                prio = parse_facility(PRIO);
        }

        SCM_ASSERT(scm_is_string(TEXT), TEXT, SCM_ARG1, FUNC_NAME);
	s = scm_to_locale_string(TEXT);
        grad_log(prio, "%s", s);
	free(s);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_log_close, "rad-log-close", 0, 0, 0,
           (),
"Close radius logging channel open by a previous call to rad-log-open.\n")
#define FUNC_NAME s_rad_log_close
{
        log_close();
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

void
rscm_radlog_init()
{
        int i;
        for (i = 0; radlog_kw[i].name; i++)
                scm_c_define(radlog_kw[i].name,
                             scm_from_int(radlog_kw[i].tok));
#include <rscm_radlog.x>
}
