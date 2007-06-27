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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#if defined(USE_PTHREAD)
# include <pthread.h>
#endif
#if defined(HAVE_SYS_SELECT_H)
# include <sys/select.h>
#endif
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <snmp/snmp_intern.h>


int snmp_errno;
struct snmp_def snmp_def = {
        0,     /* req_id */
        3,     /* retries */
        3,     /* timeout */
};

#if defined(USE_PTHREAD)
static pthread_once_t snmp_errno_once = PTHREAD_ONCE_INIT;
static pthread_key_t snmp_errno_key;

static void
snmp_errno_destroy(void *ptr)
{
        free(ptr);
}

static void
snmp_errno_create()
{
        pthread_key_create(&snmp_errno_key, snmp_errno_destroy);
}

int *
__snmp_errno_location()
{
        int *p;
        pthread_once(&snmp_errno_once, snmp_errno_create);
        p = pthread_getspecific(snmp_errno_key);
        if (!p) {
                p = malloc(sizeof(*p));
                if (!p)
                        abort ();
                *p = 0;
                pthread_setspecific(snmp_errno_key, p);
        }
        return p;
}
#else
static int __snmp_errno;

int *
__snmp_errno_location()
{
	return &__snmp_errno;
}
#endif

int
snmp_req_id()
{
        if (snmp_def.req_id == 0) {
                srand(time(NULL));
                snmp_def.req_id = random();
        }
        return snmp_def.req_id++;
}

int
snmp_fdset(struct snmp_session *sp, fd_set *fdset)
{
        int fdmax;

        fdmax = -1;
        FD_ZERO(fdset);
        for (; sp; sp = sp->next)
                if (sp->sd != -1 && sp->request_list) {
                        FD_SET(sp->sd, fdset);
                        if (sp->sd > fdmax)
                                fdmax = sp->sd;
                }
        return fdmax+1;
}

void
snmp_init(int retries, int timeout, snmp_alloc_t memalloc, snmp_free_t memfree)
{
        if (retries)
                snmp_def.retries = retries;
        if (timeout)
                snmp_def.timeout = timeout;
        if (memalloc)
                __snmp_alloc_fp = memalloc;
        if (memfree)
                __snmp_free_fp = memfree;
}

struct snmp_session *
snmp_session_create(char *community, char *host, int port,
		    snmp_cfn cfn, void *closure)
{
        struct snmp_session *sp;
        int len;
        
        sp = snmp_alloc(sizeof(*sp));

        sp->version = SNMP_VERSION_1;
        len = strlen(community);
        sp->community.str = snmp_alloc(len+1);
        if (!sp->community.str) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                snmp_free(sp);
                return NULL;
        }
        strcpy(sp->community.str, community);
        sp->community.len = len;

        sp->retries = snmp_def.retries;
        sp->timeout = snmp_def.timeout;
        
        len = strlen(host) + 1;
        sp->remote_host = snmp_alloc(len);
        if (!sp->remote_host) {
                SNMP_SET_ERRNO(E_SNMP_NOMEM);
                snmp_free(sp->community.str);
                snmp_free(sp);
                return NULL;
        }

        strcpy(sp->remote_host, host);
        sp->remote_port = port;
        sp->local_port = 0;

        sp->converse = cfn;
        sp->app_closure = closure;
        sp->pdu = NULL;
        sp->sd = -1;

        sp->next = NULL;
        sp->request_list = NULL;

        return sp;
}

int
snmp_session_open(struct snmp_session *sp, ip_addr_t local_ip,
		  int local_port, int timeout, int retries)
{
        ip_addr_t addr;
        u_short port;
        struct sockaddr_in local_sin;
        
        if (!timeout)
                sp->timeout = snmp_def.timeout;
        if (!retries)
                sp->retries = snmp_def.retries;
        if (local_ip == 0)
                local_ip = INADDR_ANY;
        sp->sd = socket(PF_INET, SOCK_DGRAM, 0);
        if (sp->sd < 0) {
                SNMP_SET_ERRNO(E_SNMP_SOCKET);
                snmp_session_free(sp);
                return -1;
        }
#ifdef SO_BSDCOMPAT
        /* For Linux only?  Prevents failing UPD packets from getting ICMP
           response. */
        {
                int one = 1;
                setsockopt(sp->sd, SOL_SOCKET, SO_BSDCOMPAT,
                           &one, sizeof(one));
        }
#endif /* SO_BSDCOMPAT */

        addr = inet_addr(sp->remote_host);
        if (addr = (ip_addr_t)-1) {
                struct hostent *hp = gethostbyname(sp->remote_host);
                if (!hp) {
                        SNMP_SET_ERRNO(E_SNMP_BAD_ADDRESS);
                        snmp_session_close(sp);
                        return -1;
                }
                addr = *(ip_addr_t *)hp->h_addr;
        }
        sp->remote_sin.sin_addr.s_addr = addr;
        sp->remote_sin.sin_family = AF_INET;

        if (sp->remote_port == 0) {
                struct servent *servp = getservbyname("snmp", "udp");
                if (!servp)
                        port = htons(SNMP_PORT);
                else
                        port = servp->s_port;
        } else
                port = htons(sp->remote_port);
        sp->remote_sin.sin_port = port;

        memset(&local_sin, '\0', sizeof(local_sin));
        local_sin.sin_family = AF_INET;
        local_sin.sin_addr.s_addr = local_ip ? INADDR_ANY : htonl(local_ip);
        local_sin.sin_port = htons(sp->local_port);

        if (bind(sp->sd, (struct sockaddr *) &local_sin, sizeof(local_sin)) < 0) {
                SNMP_SET_ERRNO(E_SNMP_BIND);
                snmp_session_close(sp);
                return -1;
        }

        return 0;
}

void
snmp_session_close(struct snmp_session *sess)
{
        if (sess->sd != -1) 
                close(sess->sd);
        snmp_session_free(sess);
}

void
snmp_session_free(struct snmp_session *sess)
{
        if (!sess)
                return;

        snmp_pdu_free(sess->pdu);
        snmp_request_free_list(sess->request_list);
        snmp_free(sess->remote_host);
        snmp_free(sess->community.str);
        snmp_free(sess);
}

void
snmp_request_free(struct snmp_request *req)
{
        if (req) {
                snmp_pdu_free(req->pdu);
                snmp_free(req);
        }
}

void
snmp_request_free_list(struct snmp_request *req)
{
        struct snmp_request *next;

        while (req) {
                next = req->next;
                snmp_free(req);
                req = next;
        }
}

