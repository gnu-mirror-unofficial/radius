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

#define RADIUS_MODULE_RADSRV_C
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

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
#include <radius.h>
#include <debugmod.h>

#undef DEBUG_ONLY 

/* Build and send a reply to the incoming request.
   Input: fd          -- Socket descriptor.
          radreq      -- The request. */

int
rad_srv_send_reply(fd, radreq)
        int fd;
        RADIUS_REQ *radreq;
{
        void *pdu;
        size_t length;

        length = rad_create_pdu(&pdu, radreq->reply_code,
                                radreq->id, radreq->vector, radreq->secret,
                                radreq->reply_pairs, radreq->reply_msg);
        if (length > 0) {
                struct sockaddr saremote;
                struct sockaddr_in *sin;
                char buf[MAX_LONGNAME];

                debug(1, ("Sending %s of id %d to %lx (nas %s)",
                          auth_code_str(radreq->reply_code), radreq->id,
			  (u_long)radreq->ipaddr,
                          nas_request_to_name(radreq, buf, sizeof buf)));
                
                sin = (struct sockaddr_in *) &saremote;
                memset ((char *) sin, '\0', sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(radreq->ipaddr);
                sin->sin_port = htons(radreq->udp_port);
#ifndef DEBUG_ONLY
                sendto(fd, pdu, length, 0,
                       &saremote, sizeof(struct sockaddr_in));
#endif
                efree(pdu);
        }
	return length;
}

#ifdef USE_LIVINGSTON_MENUS
/* Reply to the request with a CHALLENGE. Also attach any user message
   provided and a state value.
   Input: fd          -- Socket descriptor.
	  radreq      -- The request.
          msg         -- User message.
          state       -- Value of the State attribute.
*/
int
rad_srv_send_challenge(fd, radreq, msg, state)
        int fd;
        RADIUS_REQ *radreq;
        char *msg;
        char *state;
{
        void *pdu;
        size_t length;
        VALUE_PAIR *p = avp_create(DA_STATE, 0, state, 0);
	VALUE_PAIR *reply;

	reply = avl_dup(radreq->reply_pairs);
	avl_merge(&reply, &p);
        length = rad_create_pdu(&pdu, RT_ACCESS_CHALLENGE, radreq->id,
                                radreq->vector, radreq->secret, reply, msg);
	avl_free(reply);
	avl_free(p);
	
        if (length > 0) {
                struct sockaddr saremote;
                struct sockaddr_in *sin;
                char buf[MAX_LONGNAME];

                debug(1, ("Sending Challenge of id %d to %lx (nas %s)",
                          radreq->id, (u_long)radreq->ipaddr,
                          nas_request_to_name(radreq, buf, sizeof buf)));
        
                sin = (struct sockaddr_in *) &saremote;
                memset ((char *) sin, '\0', sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(radreq->ipaddr);
                sin->sin_port = htons(radreq->udp_port);

#ifndef DEBUG_ONLY
                sendto(fd, pdu, length, 0,
                       &saremote, sizeof(struct sockaddr_in));
#endif
                efree(pdu);
        }
        avp_free(p);
	return length;
}
#endif
