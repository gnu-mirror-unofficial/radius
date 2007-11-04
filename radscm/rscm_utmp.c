/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,2007
   Free Software Foundation, Inc.

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

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <libguile.h>
#include <radius/radius.h>
#include <radius/radutmp.h>
#include <radius/radscm.h>

#define RADUTMP_FIELD_LOGIN       0
#define RADUTMP_FIELD_ORIG_LOGIN  1
#define RADUTMP_FIELD_PORT        2
#define RADUTMP_FIELD_PORT_TYPE   3
#define RADUTMP_FIELD_SESSION_ID  4
#define RADUTMP_FIELD_CALLER_ID   5
#define RADUTMP_FIELD_FRAMED_IP   6
#define RADUTMP_FIELD_NAS_IP      7
#define RADUTMP_FIELD_PROTO       8
#define RADUTMP_NUM_FIELDS        9

SCM_DEFINE(rad_utmp_putent, "rad-utmp-putent", 4, 1, 0,
           (SCM STATUS,
            SCM DELAY,
            SCM LIST,
            SCM RADUTMP_FILE,
            SCM RADWTMP_FILE),
"Write the supplied data into the radutmp file. If RADWTMP_FILE is not nil"
"the constructed entry is also appended to WTMP_FILE.")
#define FUNC_NAME s_rad_utmp_putent
{
        int status;
        struct radutmp ut;
        const char *file_name;
        SCM elt;
        int num;
        
        /* status */
        SCM_ASSERT(scm_is_integer(STATUS), STATUS, SCM_ARG1, FUNC_NAME);
        status = scm_to_int(STATUS);

        /* initialize the radutmp structure */
        memset(&ut, 0, sizeof(ut));

        /* Now fill it */
        
        /* Time */
        time(&ut.time);

        /* Delay */
        if (scm_is_integer(DELAY)) 
                ut.delay = scm_to_int(DELAY);
        else if (SCM_BIGP(DELAY)) 
                ut.delay = (grad_uint32_t) scm_i_big2dbl(DELAY);
        else
                SCM_ASSERT(0,
                           DELAY, SCM_ARG2, FUNC_NAME);

        /* Rest of fields */
        SCM_ASSERT((SCM_NIMP(LIST) && SCM_CONSP(LIST)),
                   LIST, SCM_ARG3, FUNC_NAME);

        num = 0;
        while (num < RADUTMP_NUM_FIELDS &&
                !(SCM_NIMP(LIST) && LIST == SCM_EOL)) {

                elt = SCM_CAR(LIST);
                LIST = SCM_CDR(LIST);

                switch (num++) {
                case RADUTMP_FIELD_LOGIN:
                        /* login name */
                        if (!scm_is_string(elt)) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: login name should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.login, scm_i_string_chars(elt), sizeof(ut.login));
                        ut.login[sizeof(ut.login)-1] = 0;
                        break;
                        
                case RADUTMP_FIELD_ORIG_LOGIN:
                        /* original login name */
                        if (!scm_is_string(elt)) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: orig login name should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.orig_login, scm_i_string_chars(elt),
                                sizeof(ut.orig_login));
                        ut.orig_login[sizeof(ut.orig_login)-1] = 0;
                        break;

                case RADUTMP_FIELD_PORT:
                        /* port number */
                        if (!scm_is_integer(elt)) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: port number should be integer",
                                               scm_list_1(elt));
                        }
                        ut.nas_port = scm_to_int(elt);
                        break;
                        
                case RADUTMP_FIELD_SESSION_ID:
                        /* session id */
                        if (!scm_is_string(elt)) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: session ID should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.session_id, scm_i_string_chars(elt),
                                sizeof(ut.session_id));
                        ut.session_id[sizeof(ut.session_id)-1] = 0;
                        
                case RADUTMP_FIELD_NAS_IP:
                        /* NAS IP address */
                        if (scm_is_integer(elt)) 
                                ut.nas_address = scm_to_int(elt);
                        else if (SCM_BIGP(elt)) 
                                ut.nas_address = (grad_uint32_t) scm_i_big2dbl(elt);
                        else if (scm_is_string(elt)) 
                                ut.nas_address =
				    grad_ip_gethostaddr(scm_i_string_chars(elt));
                        else if (scm_is_string(elt))
                                ut.nas_address =
					grad_ip_strtoip(scm_i_string_chars(elt));
                        else 
                                scm_misc_error(FUNC_NAME,
                                               "~S: NAS IP should be IP address",
                                               scm_list_1(elt));
                        ut.nas_address = htonl(ut.nas_address);
                        break;
                        
                case RADUTMP_FIELD_FRAMED_IP:
                        /* Framed IP address */
                        if (scm_is_integer(elt)) 
                                ut.framed_address = scm_to_int(elt);
                        else if (SCM_BIGP(elt)) 
                                ut.framed_address = (grad_uint32_t) scm_i_big2dbl(elt);
                        else if (scm_is_string(elt)) 
                                ut.framed_address =
				   grad_ip_gethostaddr(scm_i_string_chars(elt));
                        else if (scm_is_string(elt))
                                ut.framed_address =
				      grad_ip_strtoip(scm_i_string_chars(elt));
                        else 
                                scm_misc_error(FUNC_NAME,
                                               "~S: Framed IP should be IP address",
                                               scm_list_1(elt));
                        ut.framed_address = htonl(ut.framed_address);
                        break;
                        
                case RADUTMP_FIELD_PROTO:
                        /* Protocol */
                        if (scm_is_integer(elt)) 
                                ut.proto = scm_to_int(elt);
                        else if (SCM_IMP(elt) && SCM_CHARP(elt)) {
                                grad_dict_value_t *dv;

                                dv = grad_value_name_to_value(
					                scm_i_string_chars(elt),
                                                        DA_FRAMED_PROTOCOL);

                                if (dv)
                                        scm_misc_error(FUNC_NAME,
                                                       "~S: Unknown proto",
                                                       scm_list_1(elt));
                                ut.proto = dv->value;
                        } else
                                scm_misc_error(FUNC_NAME,
                                    "~S: Proto should be integer or string",
                                               scm_list_1(elt));
                        break;
                        
                case RADUTMP_FIELD_PORT_TYPE:
                        /* Port type */
                        if (scm_is_integer(elt)) 
                                ut.porttype = scm_to_int(elt);
                        else if (SCM_IMP(elt) && SCM_CHARP(elt))
                                ut.porttype = SCM_CHAR(elt);
                        else
                                scm_misc_error(FUNC_NAME,
                                               "~S: Port type should be char or integer",
                                               scm_list_1(elt));
                        break;

                case RADUTMP_FIELD_CALLER_ID:
                        /* Calling station ID */
                        if (!scm_is_string(elt)) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: CLID should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.caller_id, scm_i_string_chars(elt),
                                sizeof(ut.caller_id));
                        ut.caller_id[sizeof(ut.caller_id)-1] = 0;
                        break;
                }
        }


        /* FIXME: IF (LIST == SCM_EOL) ? */

        /* Finally, put it into radutmp file */

        /* Obtain the file name */
        SCM_ASSERT(scm_is_string(RADUTMP_FILE), 
                   RADUTMP_FILE, SCM_ARG4, FUNC_NAME);

        file_name = scm_i_string_chars(RADUTMP_FILE);
        grad_utmp_putent(file_name, &ut, status);

        /* Add to wtmp if necessary */
        if (!SCM_UNBNDP(RADWTMP_FILE)) {
                SCM_ASSERT(scm_is_string(RADWTMP_FILE),
                           RADWTMP_FILE, SCM_ARG5, FUNC_NAME); 
                file_name = scm_i_string_chars(RADWTMP_FILE);
                grad_radwtmp_putent(file_name, &ut);
        }

        return scm_list_3(scm_from_long(ut.duration),
                          scm_from_long(0),
                          scm_from_long(0));
}
#undef FUNC_NAME

void
rscm_utmp_init()
{
#include <rscm_utmp.x>
}
