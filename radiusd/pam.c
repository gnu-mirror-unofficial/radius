/* This file is part of GNU Radius.
   Copyright (C) 2001,2003,2004,2006,2007,2008 Free Software Foundation, Inc.

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

#ifdef USE_PAM

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>

#include <security/pam_appl.h>

#include <radiusd.h>

struct pam_conv_data {
        /* input data */
        char *username;
        char *password;
        /* output data */
        int error;
        char *reply_msg;
};

#define XSTRDUP(s) (s) ? strdup(s) : NULL

static int
rad_pam_conv(int num_msg, const struct pam_message **msg,
             struct pam_response **resp, void *closure)
{
        int count = 0, replies = 0;
        struct pam_response *reply = NULL;
        struct pam_conv_data *data = (struct pam_conv_data *)closure;
        int rc;

        if (!data) {
                grad_log(GRAD_LOG_ERR,
                         _("rad_pam_conv(): no application-specific data passed"));
                return PAM_CONV_ERR;
        }
        
        if ((reply = calloc(num_msg, sizeof(struct pam_response))) == NULL)
                return PAM_CONV_ERR;

        rc = PAM_SUCCESS;
        for (count = 0; rc == PAM_SUCCESS && count < num_msg; count++) {
                switch (msg[count]->msg_style) {
                case PAM_PROMPT_ECHO_ON:
                        reply[replies].resp_retcode = PAM_SUCCESS;
                        reply[replies++].resp = XSTRDUP(data->username);
                        break;
                case PAM_PROMPT_ECHO_OFF:
                        reply[replies].resp_retcode = PAM_SUCCESS;
                        reply[replies++].resp = XSTRDUP(data->password);
                        break;
                case PAM_ERROR_MSG:
                case PAM_TEXT_INFO: 
                        data->reply_msg = grad_estrdup((char*)msg[count]->msg);
                        break;
                default:
                        data->error++;
                        rc = PAM_CONV_ERR;
                        break;
                }
        }
        if (replies)
                *resp = reply;
        else
                free(reply);
        return rc;
}

int
pam_pass(char *name, char *passwd, const char *pamauth, char **reply_msg)
{
        pam_handle_t *pamh = NULL;
        int rc;
        struct pam_conv_data data;
        struct pam_conv conv = {
                rad_pam_conv,
                NULL
        };
        
        /* input data */
        data.username = name;
        data.password = passwd;
        /* output data */
        data.error = 0;
        data.reply_msg = NULL;

        conv.appdata_ptr = &data;

        GRAD_DEBUG2(1, "username [%s], pamauth [%s]",  name, pamauth);

        /* fake loop needed so we don't have to use gotos */
        for (;;) {
                rc = pam_start(pamauth, name, &conv, &pamh);
                GRAD_DEBUG1(1, "pam_start: %d", rc);
                if (rc != PAM_SUCCESS)
                        break;

                rc = pam_authenticate(pamh, 0);
                GRAD_DEBUG1(1, "pam_authenticate: %d", rc);

                if (rc != PAM_SUCCESS) 
                        break;
                
                rc = pam_acct_mgmt(pamh, 0);
                break;
        }
        GRAD_DEBUG1(1, "pam_acct_mgmt: %d", rc);
        pam_end(pamh, 0);

        *reply_msg = data.reply_msg;
        
        return rc != PAM_SUCCESS;
}

#endif
