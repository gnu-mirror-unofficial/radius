/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2007, 2010 Free Software
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
        
        for (; !scm_is_null(list); list = SCM_CDR(list)) {
                SCM car = SCM_CAR(list);
                int val = 0;
                
                if (scm_is_integer(car)) 
                        val = scm_to_int(car);
                else if (scm_is_string(car)) {
			char *s = scm_to_locale_string(car);
                        val = grad_xlat_keyword(syslog_kw, s, 0);
			free(s);
		} else
                        continue; /* FIXME: warning message */
                accval |= val;
        } 
        return accval;
}

static char *log_tag;

SCM_DEFINE_PUBLIC(rad_openlog, "rad-openlog", 3, 0, 0,
		  (SCM ident, SCM option, SCM facility),
"Opens a connection to the system logger. "
"The arguments @var{ident}, @var{option} and @var{facility} have the same "
"meaning as in openlog(3).\n")
#define FUNC_NAME s_rad_openlog
{
        int opt, facl;

	if (log_tag)
		free(log_tag);
	SCM_ASSERT(scm_is_string(ident), ident, SCM_ARG1, FUNC_NAME);
	log_tag = scm_to_locale_string(ident);
        
        if (scm_is_integer(option)) {
                opt = scm_to_int(option);
        } else {
                SCM_ASSERT(scm_is_pair(option), option, SCM_ARG2, FUNC_NAME);
                opt = parse_facility(option);
        }

        if (scm_is_integer(facility)) {
                facl = scm_to_int(facility);
        } else {
                SCM_ASSERT(scm_is_pair(facility),
			   facility, SCM_ARG3, FUNC_NAME);
                facl = parse_facility(facility);
        }

        openlog(log_tag, opt, facl);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_syslog, "rad-syslog", 2, 0, 0,
		  (SCM prio, SCM text),
"Distributes @var{text} via syslogd priority @var{prio}.\n")
#define FUNC_NAME s_rad_syslog
{
        int n_prio;
	char *s;
	
	if (scm_is_integer(prio)) {
                n_prio = scm_to_int(prio);
	} else {
		SCM_ASSERT(scm_is_pair(prio), prio, SCM_ARG1, FUNC_NAME);
                n_prio = parse_facility(prio);
        }

        SCM_ASSERT(scm_is_string(text), text, SCM_ARG2, FUNC_NAME);
	s = scm_to_locale_string(text);
        syslog(n_prio, "%s", s);
	free(s);
        return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_closelog, "rad-closelog", 0, 0, 0,
		  (),
"Closes the channel to the system logger opened by a previous call to "
"@code{openlog}.\n")
#define FUNC_NAME s_rad_closelog
{
        closelog();
	free(log_tag);
	log_tag = NULL;
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
