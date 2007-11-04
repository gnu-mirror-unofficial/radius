/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2007 Free Software Foundation, Inc.

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
#include <syslog.h>
#include <radius/radius.h>
#include <radius/radscm.h>

static grad_keyword_t syslog_kw[] = {
        { "LOG_USER",     LOG_USER },   
        { "LOG_DAEMON",   LOG_DAEMON },
        { "LOG_AUTH",     LOG_AUTH },  
        { "LOG_LOCAL0",   LOG_LOCAL0 },
        { "LOG_LOCAL1",   LOG_LOCAL1 },
        { "LOG_LOCAL2",   LOG_LOCAL2 },
        { "LOG_LOCAL3",   LOG_LOCAL3 },
        { "LOG_LOCAL4",   LOG_LOCAL4 },
        { "LOG_LOCAL5",   LOG_LOCAL5 },
        { "LOG_LOCAL6",   LOG_LOCAL6 },
        { "LOG_LOCAL7",   LOG_LOCAL7 },
        /* severity */
        { "LOG_EMERG",    LOG_EMERG },    
        { "LOG_ALERT",    LOG_ALERT },   
        { "LOG_CRIT",     LOG_CRIT },    
        { "LOG_ERR",      LOG_ERR },     
        { "LOG_WARNING",  LOG_WARNING }, 
        { "LOG_NOTICE",   LOG_NOTICE },  
        { "LOG_INFO",     LOG_INFO },    
        { "LOG_DEBUG",    LOG_DEBUG },   
        /* options */
        { "LOG_CONS",     LOG_CONS },   
        { "LOG_NDELAY",   LOG_NDELAY }, 
        { "LOG_PID",      LOG_PID },
        { NULL }
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
                        val = grad_xlat_keyword(syslog_kw,
						scm_i_string_chars(car), 0);
                else
                        continue;
                accval |= val;
        } 
        return accval;
}

SCM_DEFINE(rad_openlog, "rad-openlog", 3, 0, 0,
           (SCM IDENT, SCM OPTION, SCM FACILITY),
"Scheme interface to the system openlog() call.")          
#define FUNC_NAME s_rad_openlog
{
        const char *ident;
        int option, facility;

        if (IDENT == SCM_BOOL_F)
                ident = "radius";
        else {
                SCM_ASSERT(scm_is_string(IDENT), IDENT, SCM_ARG1, FUNC_NAME);
                ident = scm_i_string_chars(IDENT);
        }
        
        if (scm_is_integer(OPTION)) {
                option = scm_to_int(OPTION);
        } else if (SCM_BIGP(OPTION)) {
                option = (grad_uint32_t) scm_i_big2dbl(OPTION);
        } else {
                SCM_ASSERT(SCM_NIMP(OPTION) && SCM_CONSP(OPTION),
                           OPTION, SCM_ARG2, FUNC_NAME);
                option = parse_facility(OPTION);
        }

        if (scm_is_integer(FACILITY)) {
                facility = scm_to_int(FACILITY);
        } else if (SCM_BIGP(FACILITY)) {
                facility = (grad_uint32_t) scm_i_big2dbl(FACILITY);
        } else {
                SCM_ASSERT(SCM_NIMP(FACILITY) && SCM_CONSP(FACILITY),
                           FACILITY, SCM_ARG3, FUNC_NAME);
                facility = parse_facility(FACILITY);
        }

        openlog(ident, option, facility);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_syslog, "rad-syslog", 2, 0, 0,
           (SCM PRIO, SCM TEXT),
"Scheme interface to the system syslog() call.")           
#define FUNC_NAME s_rad_syslog
{
        int prio;

        if (PRIO == SCM_BOOL_F) {
                prio = LOG_INFO;
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
        syslog(prio, "%s", scm_i_string_chars(TEXT));
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE(rad_closelog, "rad-closelog", 0, 0, 0,
           (),
"Scheme interface to the system closelog() call.")         
#define FUNC_NAME s_rad_closelog
{
        closelog();
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

void
rscm_syslog_init()
{
        int i;
        for (i = 0; syslog_kw[i].name; i++)
                scm_c_define(syslog_kw[i].name,
                             scm_from_int(syslog_kw[i].tok));
#include <rscm_syslog.x>
}
