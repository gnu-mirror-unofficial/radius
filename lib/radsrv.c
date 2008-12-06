/* This file is part of GNU Radius.
   Copyright (C) 2002,2003,2004,2006,2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>

#include <radlib.h>

/* Build and send a reply to the incoming request.
   Input: fd          -- Socket descriptor.
          radreq      -- The request. */

int
grad_server_send_reply(int fd, grad_request_t *radreq,
		       int reply_code, grad_avp_t *reply_pairs,
		       char *reply_msg)
{
        void *pdu;
        size_t length;

        length = grad_create_pdu(&pdu, reply_code,
				 radreq->id, radreq->authenticator,
				 radreq->secret,
				 reply_pairs, reply_msg);
        if (length > 0) {
                struct sockaddr saremote;
                struct sockaddr_in *sin;
                char buf[GRAD_MAX_LONGNAME];

                sin = (struct sockaddr_in *) &saremote;
                memset ((char *) sin, '\0', sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(radreq->ipaddr);
                sin->sin_port = htons(radreq->udp_port);
#ifdef DEBUG_ONLY
		grad_log(GRAD_LOG_DEBUG,
			 "DEBUG_ONLY version: not sending %s of id %d to %s (nas %s)",
			 grad_request_code_to_name(reply_code), 
			 radreq->id,
			 grad_ip_iptostr(radreq->ipaddr, NULL),
			 grad_nas_request_to_name(radreq, buf, sizeof buf));
#else		
                GRAD_DEBUG4(1, "Sending %s of id %d to %s (nas %s)",
                          grad_request_code_to_name(reply_code), 
                          radreq->id,
			  grad_ip_iptostr(radreq->ipaddr, NULL),
                          grad_nas_request_to_name(radreq, buf, sizeof buf));
                
                sendto(fd, pdu, length, 0,
                       &saremote, sizeof(struct sockaddr_in));
#endif
		grad_free(pdu);
        }
	return length;
}

/* Reply to the request with a CHALLENGE. Also attach any user message
   provided and a state value.
   Input: fd          -- Socket descriptor.
	  radreq      -- The request.
          msg         -- User message.
          state       -- Value of the State attribute.
*/
int
grad_server_send_challenge(int fd, grad_request_t *radreq,
			   grad_avp_t *reply_pairs, char *msg, char *state)
{
        void *pdu;
        size_t length;
        grad_avp_t *p = grad_avp_create_string(DA_STATE, state);
	grad_avp_t *reply;

	reply = grad_avl_dup(reply_pairs);
	grad_avl_merge(&reply, &p);
        length = grad_create_pdu(&pdu, RT_ACCESS_CHALLENGE, radreq->id,
				 radreq->authenticator, radreq->secret,
				 reply, msg);
	grad_avl_free(reply);
	grad_avl_free(p);
	
        if (length > 0) {
                struct sockaddr saremote;
                struct sockaddr_in *sin;
                char buf[GRAD_MAX_LONGNAME];

                sin = (struct sockaddr_in *) &saremote;
                memset ((char *) sin, '\0', sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(radreq->ipaddr);
                sin->sin_port = htons(radreq->udp_port);

#ifdef DEBUG_ONLY
		grad_log(GRAD_LOG_DEBUG,
			 "DEBUG_ONLY version: not sending challenge of id %d to %s (nas %s)",
			 radreq->id, grad_ip_iptostr(radreq->ipaddr, NULL),
			 grad_nas_request_to_name(radreq, buf, sizeof buf)));
#else
                GRAD_DEBUG3(1, "Sending Challenge of id %d to %s (nas %s)",
                          radreq->id, grad_ip_iptostr(radreq->ipaddr, NULL),
                          grad_nas_request_to_name(radreq, buf, sizeof buf));
        
                sendto(fd, pdu, length, 0,
                       &saremote, sizeof(struct sockaddr_in));
#endif
                grad_free(pdu);
        }
        grad_avp_free(p);
	return length;
}

