/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

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

#include <radius.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <libguile.h>
#include <radutmp.h>
#include <radscm.h>

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
"Write the supplied data into the radutmp file. If RADWTMP_FILE is not nil
the constructed entry is also appended to WTMP_FILE.")
#define FUNC_NAME s_rad_utmp_putent
{
        int status;
        struct radutmp ut;
        char *file_name;
        SCM elt;
        int num;
        
        /* status */
        SCM_ASSERT(SCM_IMP(STATUS) && SCM_INUMP(STATUS),
                   STATUS, SCM_ARG1, FUNC_NAME);
        status = SCM_INUM(STATUS);

        /* initialize the radutmp structure */
        memset(&ut, 0, sizeof(ut));

        /* Now fill it */
        
        /* Time */
        time(&ut.time);

        /* Delay */
        if (SCM_IMP(DELAY) && SCM_INUMP(DELAY)) 
                ut.delay = SCM_INUM(DELAY);
        else if (SCM_BIGP(DELAY)) 
                ut.delay = (UINT4) scm_i_big2dbl(DELAY);
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
                        if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: login name should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.login, SCM_STRING_CHARS(elt), sizeof(ut.login));
                        ut.login[sizeof(ut.login)-1] = 0;
                        break;
                        
                case RADUTMP_FIELD_ORIG_LOGIN:
                        /* original login name */
                        if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: orig login name should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.orig_login, SCM_STRING_CHARS(elt),
                                sizeof(ut.orig_login));
                        ut.orig_login[sizeof(ut.orig_login)-1] = 0;
                        break;

                case RADUTMP_FIELD_PORT:
                        /* port number */
                        if (!(SCM_IMP(elt) && SCM_INUMP(elt))) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: port number should be integer",
                                               scm_list_1(elt));
                        }
                        ut.nas_port = SCM_INUM(elt);
                        break;
                        
                case RADUTMP_FIELD_SESSION_ID:
                        /* session id */
                        if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: session ID should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.session_id, SCM_STRING_CHARS(elt),
                                sizeof(ut.session_id));
                        ut.session_id[sizeof(ut.session_id)-1] = 0;
                        
                case RADUTMP_FIELD_NAS_IP:
                        /* NAS IP address */
                        if (SCM_IMP(elt) && SCM_INUMP(elt)) 
                                ut.nas_address = SCM_INUM(elt);
                        else if (SCM_BIGP(elt)) 
                                ut.nas_address = (UINT4) scm_i_big2dbl(elt);
                        else if (SCM_NIMP(elt) && SCM_STRINGP(elt)) 
                                ut.nas_address = ip_gethostaddr(SCM_STRING_CHARS(elt));
                        else if (SCM_NIMP(elt) && SCM_STRINGP(elt))
                                ut.nas_address = ip_strtoip(SCM_STRING_CHARS(elt));
                        else 
                                scm_misc_error(FUNC_NAME,
                                               "~S: NAS IP should be IP address",
                                               scm_list_1(elt));
                        ut.nas_address = htonl(ut.nas_address);
                        break;
                        
                case RADUTMP_FIELD_FRAMED_IP:
                        /* Framed IP address */
                        if (SCM_IMP(elt) && SCM_INUMP(elt)) 
                                ut.framed_address = SCM_INUM(elt);
                        else if (SCM_BIGP(elt)) 
                                ut.framed_address = (UINT4) scm_i_big2dbl(elt);
                        else if (SCM_NIMP(elt) && SCM_STRINGP(elt)) 
                                ut.framed_address = ip_gethostaddr(SCM_STRING_CHARS(elt));
                        else if (SCM_NIMP(elt) && SCM_STRINGP(elt))
                                ut.framed_address = ip_strtoip(SCM_STRING_CHARS(elt));
                        else 
                                scm_misc_error(FUNC_NAME,
                                               "~S: Framed IP should be IP address",
                                               scm_list_1(elt));
                        ut.framed_address = htonl(ut.framed_address);
                        break;
                        
                case RADUTMP_FIELD_PROTO:
                        /* Protocol */
                        if (SCM_IMP(elt) && SCM_INUMP(elt)) 
                                ut.proto = SCM_INUM(elt);
                        else if (SCM_IMP(elt) && SCM_CHARP(elt)) {
                                DICT_VALUE *dv;

                                dv = value_name_to_value(SCM_STRING_CHARS(elt),
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
                        if (SCM_IMP(elt) && SCM_INUMP(elt)) 
                                ut.porttype = SCM_INUM(elt);
                        else if (SCM_IMP(elt) && SCM_CHARP(elt))
                                ut.porttype = SCM_CHAR(elt);
                        else
                                scm_misc_error(FUNC_NAME,
                                               "~S: Port type should be char or integer",
                                               scm_list_1(elt));
                        break;

                case RADUTMP_FIELD_CALLER_ID:
                        /* Calling station ID */
                        if (!(SCM_NIMP(elt) && SCM_STRINGP(elt))) {
                                scm_misc_error(FUNC_NAME,
                                               "~S: CLID should be string",
                                               scm_list_1(elt));
                        }
                        strncpy(ut.caller_id, SCM_STRING_CHARS(elt),
                                sizeof(ut.caller_id));
                        ut.caller_id[sizeof(ut.caller_id)-1] = 0;
                        break;
                }
        }


        /* FIXME: IF (LIST == SCM_EOL) ? */

        /* Finally, put it into radutmp file */

        /* Obtain the file name */
        SCM_ASSERT(SCM_NIMP(RADUTMP_FILE) && SCM_STRINGP(RADUTMP_FILE),
                   RADUTMP_FILE, SCM_ARG4, FUNC_NAME);

        file_name = SCM_STRING_CHARS(RADUTMP_FILE);
        radutmp_putent(file_name, &ut, status);

        /* Add to wtmp if necessary */
        if (!SCM_UNBNDP(RADWTMP_FILE)) {
                SCM_ASSERT(SCM_NIMP(RADWTMP_FILE) && SCM_STRINGP(RADWTMP_FILE),
                           RADWTMP_FILE, SCM_ARG5, FUNC_NAME); 
                file_name = SCM_STRING_CHARS(RADWTMP_FILE);
                radwtmp_putent(file_name, &ut);
        }

        return scm_list_3(scm_long2num(ut.duration),
                         scm_long2num(0),
                         scm_long2num(0));
}
#undef FUNC_NAME

void
rscm_utmp_init()
{
#include <rscm_utmp.x>
}
