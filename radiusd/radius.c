/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_RADIUS_C
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radiusd.h>

/* Build and send a reply to the incoming request.
   Input: code        -- Reply code.
          radreq      -- The request.
          reply_pairs -- List of A/V pairs to be encoded in the reply
          msg         -- User message
          fd          -- Socket descriptor.
    NOTE: If radreq contains cached reply information, this information
          is used instead of the supplied arguments. */

void
rad_send_reply(code, radreq, reply_pairs, msg, fd)
        int code;
        RADIUS_REQ *radreq;
        VALUE_PAIR *reply_pairs;
        char *msg;
        int fd;
{
        void *pdu;
        char *what;
        size_t length;

        if (radreq->reply_code == 0) {
                VALUE_PAIR *reply;
                
                /* Save the data */
                radreq->reply_code = code;
                radreq->reply_msg = estrdup(msg);

                reply = avl_dup(reply_pairs);
                avl_move_attr(&reply, &radreq->request, DA_PROXY_STATE);
                
                switch (code) {
                case RT_PASSWORD_REJECT:
                case RT_AUTHENTICATION_REJECT:
                        radreq->reply_pairs = NULL;
                        avl_move_attr(&radreq->reply_pairs, &reply, 
                                      DA_REPLY_MESSAGE);
                        avl_move_attr(&radreq->reply_pairs, &reply, 
                                      DA_PROXY_STATE);
                        avl_free(reply);
                        break;

                default:
                        radreq->reply_pairs = reply;
                }
        } 

	rad_srv_send_reply(fd, radreq);
}
	
#ifdef USE_LIVINGSTON_MENUS
/* Reply to the request with a CHALLENGE. Also attach any user message
   provided and a state value.
   Input: radreq      -- The request.
          msg         -- User message.
          state       -- Value of the State attribute.
          fd          -- Socket descriptor. */
void
send_challenge(radreq, msg, state, fd)
        RADIUS_REQ *radreq;
        char *msg;
        char *state;
        int fd;
{
	if (rad_srv_send_challenge(fd, radreq, msg, state))
		stat_inc(auth, radreq->ipaddr, num_challenges);
}
#endif

/* Validates the requesting client NAS. */
int
validate_client(radreq)
        RADIUS_REQ *radreq;
{
        CLIENT  *cl;
        char buf[MAX_LONGNAME];
        
        if ((cl = client_lookup_ip(radreq->ipaddr)) == NULL) {
                radlog_req(L_ERR, radreq, _("request from unknown client"));
                return -1;
        }

        /* Save the secret key */
        radreq->secret = cl->secret;

        return 0;
}

/* Validates the requesting NAS */
int
calc_acctdigest(radreq)
        RADIUS_REQ *radreq;
{
        int     secretlen;
        char zero[AUTH_VECTOR_LEN];
        u_char  *recvbuf;
        int     len = radreq->data_len;
        u_char digest[AUTH_VECTOR_LEN];

        secretlen = strlen(radreq->secret);

        recvbuf = emalloc(len + secretlen);
        memcpy(recvbuf, radreq->data, len + secretlen);
        
        /* Older clients have the authentication vector set to
           all zeros. Return `1' in that case. */
        memset(zero, 0, sizeof(zero));
        if (memcmp(radreq->vector, zero, AUTH_VECTOR_LEN) == 0)
                return REQ_AUTH_ZERO;

        /* Zero out the auth_vector in the received packet.
           Then append the shared secret to the received packet,
           and calculate the MD5 sum. This must be the same
           as the original MD5 sum (radreq->vector). */
        memset(recvbuf + 4, 0, AUTH_VECTOR_LEN);
        memcpy(recvbuf + len, radreq->secret, secretlen);
        md5_calc(digest, recvbuf, len + secretlen);
        efree(recvbuf);
        
        return memcmp(digest, radreq->vector, AUTH_VECTOR_LEN) ?
                          REQ_AUTH_BAD : REQ_AUTH_OK;
}

