/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_SOCKLIST_C

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
#include <unistd.h>
#include <errno.h>
#include <radiusd.h>

/* Socket lists */
struct socket_list {
        SOCKET_LIST *next;
	UINT4 ipaddr;
	int port;
	int type;
        int fd;
};

static int open_socket(UINT4 ipaddr, int port, int type);
static SOCKET_LIST *socket_list_alloc(int type, UINT4 ipaddr, int port);

/* Make sure recv_buffer is aligned properly. */
static int i_recv_buffer[RAD_BUFFER_SIZE];
static u_char *recv_buffer = (u_char *)i_recv_buffer;

SOCKET_LIST *
socket_list_alloc(type, ipaddr, port)
	int type;
	UINT4 ipaddr;
	int port;
{
	SOCKET_LIST *s = alloc_entry(sizeof(*s));
	s->type = type;
	s->ipaddr = ipaddr;
	s->port = port;
	s->fd = -1;
	return s;
}

int
socket_list_add(slist, type, ipaddr, port)
	SOCKET_LIST **slist;
	int type;
	UINT4 ipaddr;
	int port;
{
	SOCKET_LIST *p, *last = NULL;
	
	if (!*slist) {
		*slist = socket_list_alloc(type, ipaddr, port);
		return 0;
	}

	for (p = *slist; p; p = p->next) {
		last = p;
		if (p->port == port && p->ipaddr == ipaddr) {
			if (p->type == R_NONE) {
				p->type = type;
				return 0;
			} else {
				char buffer[DOTTED_QUAD_LEN];
				radlog(L_ERR,
				       _("socket %s:%d is already assigned for %s"),
				       ip_iptostr(ipaddr, buffer),
				       port,
				       request_class[p->type].name);
				return 1;
			}
		}
	}
	last->next = socket_list_alloc(type, ipaddr, port);
	return 0;
}

void
socket_list_init(slist)
	SOCKET_LIST *slist;
{
	for (;slist; slist = slist->next) 
		slist->type = R_NONE;
}

int
open_socket(ipaddr, port, type)
        UINT4 ipaddr;
        int port;
        int type;
{
        struct  sockaddr salocal;
        struct  sockaddr_in *sin;

        int fd = socket (AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
                radlog(L_CRIT|L_PERROR, "%s socket",
		       request_class[type].name);
		return -1;
        }

        sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(ipaddr);
        sin->sin_port = htons(port);

        if (bind (fd, & salocal, sizeof (*sin)) < 0) {
                radlog(L_CRIT|L_PERROR, "%s bind", request_class[type].name);
		close(fd);
		fd = -1;
        }
        return fd;
}

int
socket_list_open(slist)
	SOCKET_LIST **slist;
{
	SOCKET_LIST *p, *prev = NULL;
	int count = 0;
	
	for (p = *slist; p;) {
		SOCKET_LIST *next = p->next;

		if (p->type == R_NONE) {
			debug(1, ("deleting unused socket: %x:%d",
				  p->ipaddr, p->port));
			if (prev)
				prev->next = next;
			else
				*slist = next;
			if (p->fd != -1)
				close(p->fd);
			free_entry(p);
		}
		p = next;
	}
	
	for (p = *slist; p;) {
		SOCKET_LIST *next = p->next;
		if (p->fd == -1) {
			debug(1, ("opening new socket: %x:%d for %s",
				p->ipaddr, p->port,
				request_class[p->type].name));

			p->fd = open_socket(p->ipaddr, p->port, p->type);
			if (p->fd == -1) {
				debug(1, ("deleting failed socket: %x:%d",
					  p->ipaddr, p->port));
				if (prev)
					prev->next = next;
				else
					*slist = next;
				free_entry(p);
			} else
				count++;
		} else
			count++;
		p = next;
	}
	debug(1, ("opened %d sockets", count));
	return count;
}

void
socket_list_close(slist)
	SOCKET_LIST **slist;
{
	SOCKET_LIST *p;
	
	for (p = *slist; p;) {
		SOCKET_LIST *next = p->next;
		close(p->fd);
		free_entry(p);
		p = next;
	}
	*slist = NULL;
}

void
socket_list_iterate(slist, fun)
	SOCKET_LIST *slist;
	void (*fun)();
{
	for (; slist; slist = slist->next) 
		fun(slist->type, slist->fd);
}

int
socket_list_select(list, ht, numh, tv)
        struct socket_list *list;
	struct request_handler_tab *ht;
	size_t numh;
        struct timeval *tv;
{
        int result;
        int status;
        int salen;
        struct sockaddr saremote;
        fd_set readfds;
        struct socket_list *ctl;
        int max_fd = 0;

        FD_ZERO(&readfds);
        for (ctl = list; ctl; ctl = ctl->next) {
                FD_SET(ctl->fd, &readfds);
                if (ctl->fd > max_fd)
                        max_fd = ctl->fd;
        }

        debug(100,("selecting (%d fds)", max_fd+1));
        status = select(max_fd + 1, &readfds, NULL, NULL, tv);
        
        if (status == -1) {
                if (errno == EINTR) 
                        return 0;
                return -1;
        } else if (status == 0) 
                return 0;
        debug(100,("processing..."));
        for (ctl = list; ctl; ctl = ctl->next) {
                if (FD_ISSET(ctl->fd, &readfds) && ctl->type < numh) {
                        salen = sizeof (saremote);
                        result = recvfrom (ctl->fd, (char *) recv_buffer,
					   (int) sizeof(i_recv_buffer),
					   (int) 0, &saremote, &salen);

                        if (ht[ctl->type].success)
                                ht[ctl->type].success(&saremote, salen);
                        if (result > 0) {
                                debug(100,("calling respond"));
                                ht[ctl->type].respond(ctl->fd,
						      &saremote, salen,
						      recv_buffer, result);
                                debug(100,("finished respond"));
                        } else if (result < 0 && errno == EINTR) {
                                if (ht[ctl->type].failure)
                                        ht[ctl->type].failure(&saremote,
							      salen);
                                result = 0;
                        }
                }
        }
        return 0;
}
