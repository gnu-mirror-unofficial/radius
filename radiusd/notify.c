/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
#define RADIUS_MODULE 8
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef USE_NOTIFY

#ifndef lint
static char rcsid[] = 
 "@(#) $Id$";
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <radiusd.h>

#include <varargs.h>

struct handshake_packet {
	char len;
	char text[1];
};

struct notify_packet {
	char len;
	char stat;
	char name[1];
};

Notify notify_cfg;
int    sockfd;

int _notify( char *login, char *called_id, int what, long *ttl_ptr );

int
_notify(login, called_id, what, ttl_ptr)
	char *login;
	char *called_id;
	int what;
	long *ttl_ptr;
{
	struct sockaddr salocal;
	struct sockaddr saremote;
	struct sockaddr_in *sin;
	struct timeval  authtime;
	fd_set          readfds;
	int             salen;
	int             total_length;
	int             length;
	int             result = -1;
	int             i;
	char            recv_buffer[1024];
	char            send_buffer[1024];
	struct handshake_packet *hpack;
	struct notify_packet *pack;
	long ttl;
	char *p;
	
	if (notify_cfg.ipaddr == 0)
		return 1;

	pack = (struct notify_packet *) send_buffer;
	strcpy(pack->name, login);
	total_length = sizeof(struct notify_packet) +
		strlen(pack->name);

	switch (what) {
	case DV_ACCT_STATUS_TYPE_START:
		what = '+';
		break;
	case DV_ACCT_STATUS_TYPE_STOP:
		what = '-';
		pack->name[strlen(pack->name)+1] = 0;
		break;
	case DV_ACCT_STATUS_TYPE_QUERY:
		*ttl_ptr = 0;
		what = '?';
		pack->name[strlen(pack->name)+1] = 0;
		break;
	default:
		return -1;
	}
	pack->stat = what;
	pack->len = total_length;
	
	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)	{
		radlog(L_ERR|L_PERROR, _("notify(): socket"));
		return -1;
	}

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = INADDR_ANY;
	sin->sin_port = htons ((unsigned short) 0);
	if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||
	    getsockname (sockfd, (struct sockaddr *) sin, &length) < 0) {
		close (sockfd);
		radlog(L_ERR|L_PERROR, "notify(): bind");
		return -1;
	}
	

	sin = (struct sockaddr_in *) & saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl (notify_cfg.ipaddr);
	sin->sin_port = htons ((unsigned short) notify_cfg.port);

	for (i = 0; i < notify_cfg.retry; i++) {
		debug(1, ("sent %d %c %s",
		     pack->len,
		     pack->stat,
		     pack->name));

		sendto(sockfd, (char *) pack, (unsigned int) total_length,
		       (int) 0,
		       (struct sockaddr *) sin,
		       sizeof(struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) notify_cfg.timeout;
		FD_ZERO (&readfds);
		FD_SET (sockfd, &readfds);
		if (select (sockfd + 1, &readfds, NULL, NULL, &authtime) < 0) {
			if (errno == EINTR)
				continue;
			radlog(L_ERR|L_PERROR, "notify(): select");
			close(sockfd);
			return -1;
		}
	
		if (FD_ISSET (sockfd, &readfds)) {
			salen = sizeof (saremote);
			length = recvfrom (sockfd, (char *) recv_buffer,
					   (int) sizeof (recv_buffer),
					   (int) 0, &saremote, &salen);

			if (length <= 0) {
				radlog(L_ERR|L_PERROR, 
					"notify(): recvfrom: %s:%d",
				    	ip_hostname(notify_cfg.ipaddr), 
					notify_cfg.port);
				close (sockfd);
				return -1;
			}
			
			hpack = (struct handshake_packet *)recv_buffer;
			debug(1,("received %d %-10.10s",
			     hpack->len,
			     hpack->text));
		
			switch (what) {
			case '+':
			case '-':
				if (strcmp(hpack->text, "OK") == 0) {
					debug(1,
					     ("user `%s' %s",
					     login,
					     what == '+' ? "entered" : "left"));
					result = 0;
				} else {
					radlog(L_ERR,
					    _("bad answer from %s:%u (%10.10s)"),
					    ip_hostname(notify_cfg.ipaddr), notify_cfg.port,
					    hpack->text);
					result = -1;
				}
				break;
			case '?':
				if (hpack->text[0] == '-') {
					result = 1;
				} else {
					ttl = strtol(hpack->text, &p, 0);
					if (*p) {
						radlog(L_ERR,
						    _("bad answer from %s:%u (`%10.10s' stopped at %c)"),
						    ip_hostname(notify_cfg.ipaddr), notify_cfg.port,
						    hpack->text,
						    *p);
						ttl = 0;
					}
					result = 0;
					*ttl_ptr = ttl;
				}
			}
			break;
		}
	}

	if (result < 0) {
		radlog(L_ERR, _("no response from %s:%u"),
		    ip_hostname(notify_cfg.ipaddr), notify_cfg.port);
	}
	
	close(sockfd);
	return result;
}

int
notify(login, what, ttl_ptr)
	char *login;
	int what;
	long *ttl_ptr;
{
	return _notify(login, NULL, what, ttl_ptr);
}

int
notify_acct(login, what, called_id)
	char *login;
	int what;
	char *called_id;
{
	return _notify(login, called_id, what, NULL);
}

int
timetolive(user_name, ttl)
	char *user_name;
	long *ttl;
{
	return notify(user_name, DV_ACCT_STATUS_TYPE_QUERY, ttl);
}

#endif
