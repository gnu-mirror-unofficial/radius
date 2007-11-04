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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius/radius.h>
#include <radius/radscm.h>

static grad_keyword_t radlog_kw[] = {
#define D(c) { #c, c }
        /* log categories */
        D(L_MAIN),
        D(L_AUTH),
        D(L_ACCT),
        D(L_PROXY),
        D(L_SNMP),
        /* log priorities */
        D(L_EMERG),
        D(L_ALERT),
        D(L_CRIT),
        D(L_ERR),
        D(L_WARN),
        D(L_NOTICE),
        D(L_INFO),
        D(L_DEBUG),
        { NULL }
#undef D
};

static int
parse_facility(SCM list)
{
        int accval = 0;
        for (; list != SCM_EOL; list = SCM_CDR(list)) {
                SCM car = SCM_CAR(list);
                int val = 0;
                
                if (scm_is_integer(car)) 
                        val = scm_to_int(car);
                else if (scm_is_string(car))
                        val = grad_xlat_keyword(radlog_kw,
						scm_i_string_chars(car), 0);
                else if (SCM_BIGP(car)) 
		  val = (grad_uint32_t) scm_i_big2dbl(car);
                else
                        continue;
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
        } else if (SCM_BIGP(PRIO)) {
                prio = (grad_uint32_t) scm_i_big2dbl(PRIO);
        } else {
                SCM_ASSERT(SCM_NIMP(PRIO) && SCM_CONSP(PRIO),
                           PRIO, SCM_ARG1, FUNC_NAME);
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
        if (PRIO == SCM_BOOL_F) {
                prio = L_INFO;
        } else if (scm_is_integer(PRIO)) {
                prio = scm_to_int(PRIO);
        } else if (SCM_BIGP(PRIO)) {
                prio = (grad_uint32_t) scm_i_big2dbl(PRIO);
        } else {
                SCM_ASSERT(SCM_NIMP(PRIO) && SCM_CONSP(PRIO),
                           PRIO, SCM_ARG1, FUNC_NAME);
                prio = parse_facility(PRIO);
        }

        SCM_ASSERT(scm_is_string(TEXT), TEXT, SCM_ARG1, FUNC_NAME);
        grad_log(prio, "%s", scm_i_string_chars(TEXT));
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
