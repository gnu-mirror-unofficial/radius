/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001,2003,2004,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#if defined(HAVE_SYS_SELECT_H)
# include <sys/select.h>
#endif
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <snmp/snmp_intern.h>

void snmp_read();

int
snmp_query(struct snmp_session *sess, struct snmp_pdu *pdu)
{
        if (snmp_send(sess, pdu))
                return -1;
        snmp_poll(sess);
        return 0;
}
        
void
snmp_poll(struct snmp_session *sess)
{
        int rc;
        int numfds;
        fd_set fdset;
        struct timeval timeout;
        
        while (numfds = snmp_fdset(sess, &fdset)) {
                timeout.tv_usec = 0;
                timeout.tv_sec = 1;
                rc = select(numfds, &fdset, NULL, NULL, &timeout);
                if (rc < 0) {
                        if (errno == EINTR)
                                continue;
                        break;
                } else if (rc == 0) {
                        snmp_timeout(sess);
                } else {
                        snmp_read(sess, &fdset);
                }
        } 
}

void
snmp_timeout(struct snmp_session *sess)
{
        struct snmp_session *sp;
        struct snmp_request *req, *preq;
        struct timeval now;

        gettimeofday(&now, (struct timezone *) 0);
        for (sp = sess; sp; sp = sp->next) {

                if (sp->sd < 0) 
                        continue;

                preq = NULL;
                req = sp->request_list;
                while (req) {
                        if (timercmp(&req->expire, &now, <)) {
                                if (req->retries > sp->retries) {
                                        sp->converse(SNMP_CONV_TIMEOUT,
                                                     sp, req->pdu,
                                                     sp->app_closure);
                                        if (preq) {
                                                preq->next = req->next;
                                                snmp_request_free(req);
                                                req = preq->next;
                                        } else {
                                                sp->request_list = req->next;
                                                snmp_request_free(req);
                                                req = sp->request_list;
                                        }
                                        continue;
                                } else {
                                        req->retries++;
                                        req->timeout <<= 1;
                                        snmp_request_xmit(sp, req);
                                }
                        }
                        preq = req;
                        req = req->next;
                }
        }
}

void
snmp_read(struct snmp_session *sess, fd_set *fdset)
{
        struct snmp_session *sp;
        struct snmp_request *req, *prev;
        struct snmp_pdu *pdu;
        u_char packet[SNMP_PACKET_LENGTH];
        struct sockaddr_in sin;
        int salen;
        int length;
        char comm[128];
        int comm_len;
        
        for (sp = sess; sp; sp = sp->next) {
                if (sp->sd < 0 || !FD_ISSET(sp->sd, fdset))
                        continue;

                /* read the data */
                salen = sizeof(sin);
                length = recvfrom(sp->sd,
                                  (char*) packet, sizeof(packet),
                                  0, (struct sockaddr *)&sin,
                                  &salen);
                if (length == -1) {
                        perror("recvfrom");/*FIXME */
                        continue;
                }
                /* create PDU and parse the packet */
                pdu = snmp_pdu_create(0);
                if (!pdu) {
                        /*FIXME: issue error msg?*/
                        continue;
                }
                pdu->peer_sin = sin;
                pdu->req_id = 0;
                comm_len = sizeof(comm)-1;
                if (snmp_decode_request(sp, pdu, packet, length,
                                         comm, &comm_len)) {
                        /*FIXME: error messg*/
                        snmp_pdu_free(pdu);
                        continue;
                }

                if (pdu->type == SNMP_PDU_RESPONSE) {
                        if (strcmp(sp->community.str, comm)) {
                                if (sp->converse(SNMP_CONV_COMMUNITY_MISMATCH,
                                                 sp, pdu,
                                                 sp->app_closure)) {
                                        snmp_pdu_free(pdu);
                                        continue;
                                }
                        }
                } else {
                        char *p = snmp_alloc(comm_len+1);
                        if (!p) {
                                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                                snmp_pdu_free(pdu);
                                continue;
                        }
                        
                        strcpy(sp->community.str, comm);
                        if (sp->community.str)
                                snmp_free(sp->community.str);
                        sp->community.str = p;
                        sp->community.len = comm_len;
                }
                
                switch (pdu->type) {
                case SNMP_PDU_RESPONSE:
                        prev = NULL;
                        for (req = sp->request_list;
                             req && req->pdu->req_id != pdu->req_id;
                             req = req->next)
                                prev = req;
                        if (!req) {
                                /*FIXME: no matching request!!!!*/
                                snmp_pdu_free(pdu);
                                continue;
                        }
                        if (sp->converse(SNMP_CONV_RECV_MSG, sp, pdu,
                                         sp->app_closure)) {
                                /*delete request*/
                                if (!prev)
                                        sp->request_list = req->next;
                                else
                                        prev->next = req->next;
                                snmp_request_free(req);
                        }
                        break;
                case SNMP_PDU_GET:
                case SNMP_PDU_GETNEXT:
                case SNMP_PDU_SET:
                        sp->converse(SNMP_CONV_RECV_MSG, sp, pdu,
                                     sp->app_closure);
                        break;
                default:
                        /*FIXME:mesg*/ ;
                }
                snmp_pdu_free(pdu);
        }
}
