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
static char rcsid[] = 
"$Id$";

#define RADIUS_MODULE 3
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#define _XPG4_2
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#include <obstack1.h>
#include <radiusd.h>
#include <radutmp.h>
#include <checkrad.h>

int Tflag = 1;
#define MIN(a,b) ((a)<(b))?(a):(b)

/* Return values:
 *        0 == user not logged in
 *        1 == user logged in
 *       -1 == don't know
 */
int
netfinger(host, port)
	char *host;
	int port;
{
	extern int Tflag;
	char namebuf[RUT_NAMESIZE+1];
	int namelen;
	register FILE *fp;
	register int c, lastc;
	struct in_addr defaddr;
	struct hostent *hp, def;
	struct sockaddr_in sin;
	int i;
	int s;
	char *alist[1];
	struct iovec iov[3];
	struct msghdr msg;
	int found = 0;
	struct obstack stk;
	char *ptr;
	
	/* Copy at most RUT_NAMESIZE bytes from the user name */
	ptr = username;
	for (i = 0; i < RUT_NAMESIZE && *ptr; ++ptr, ++i)
		namebuf[i] = *ptr;
	namebuf[i] = 0;
	namelen = i;

	if (isdigit(*host) && (defaddr.s_addr = inet_addr(host)) != -1) {
		def.h_name = host;
		def.h_addr_list = alist;
		def.h_addr = (char *)&defaddr;
		def.h_length = sizeof(struct in_addr);
		def.h_addrtype = AF_INET;
		def.h_aliases = 0;
		hp = &def;
	} else if (!(hp = gethostbyname(host))) {
		logit(L_ERR, _("unknown host: %s"), host);
		return -1;
	}

	if (!port) {
		struct servent *sp;
		
		if (!(sp = getservbyname("finger", "tcp"))) {
			logit(L_ERR, _("tcp/finger: unknown service"));
			return -1;
		}
		port = sp->s_port;
	} else
		port = htons(port);
	
	sin.sin_family = hp->h_addrtype;
	memcpy(&sin.sin_addr, hp->h_addr,
	       MIN(hp->h_length,sizeof(sin.sin_addr)));
	sin.sin_port = port;
	if ((s = socket(hp->h_addrtype, SOCK_STREAM, 0)) < 0) {
		logit(L_ERR|L_PERROR, "socket");
		return -1;
	}

	/* have network connection; identify the host connected with */
	debug(1,("connected to %s", hp->h_name));

	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof sin;
	msg.msg_iov = iov;
	msg.msg_iovlen = 0;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	
	/* send the name followed by <CR><LF> */
	iov[msg.msg_iovlen].iov_base = namebuf;
	iov[msg.msg_iovlen++].iov_len = namelen;
	iov[msg.msg_iovlen].iov_base = "\r\n";
	iov[msg.msg_iovlen++].iov_len = 2;

	/* -T disables T/TCP: compatibility option to finger broken hosts */
	if (Tflag && connect(s, (struct sockaddr *)&sin, sizeof (sin))) {
		logit(L_ERR|L_PERROR, "connect");
		return -1;
	}

	if (sendmsg(s, &msg, 0) < 0) {
		logit(L_ERR|L_PERROR, "sendmsg");
		close(s);
		return -1;
	}

	obstack_init(&stk);
	/*
	 * Read from the remote system; once we're connected, we assume some
	 * data.  If none arrives, we hang until the user interrupts.
	 *
	 * If we see a <CR> or a <CR> with the high bit set, treat it as
	 * a newline; if followed by a newline character, only output one
	 * newline.
	 *
	 * Otherwise, all high bits are stripped; if it isn't printable and
	 * it isn't a space, we can simply set the 7th bit.  Every ASCII
	 * character with bit 7 set is printable.
	 */
	lastc = 0;
	if ((fp = fdopen(s, "r")) != NULL) {
		while ((c = getc(fp)) != EOF) {
			if (c == 0x0d) {
				if (lastc == '\r')	/* ^M^M - skip dupes */
					continue;
				c = '\n';
				lastc = '\r';
			} else {
				if (!isprint(c) && !isspace(c)) {
					c &= 0x7f;
					c |= 0x40;
				}
				if (lastc != '\r' || c != '\n')
					lastc = c;
				else {
					lastc = '\n';
					continue;
				}
			}
			obstack_1grow(&stk, c);
			if (c == '\n') {
				obstack_1grow(&stk, 0);
				ptr = obstack_finish(&stk);
				debug(2,("got : %s", ptr));
				found = compare(ptr);
				obstack_free(&stk, ptr);
				if (found) 
					break;
			}
		}
		
		if (!found && lastc != '\n') {
			obstack_1grow(&stk, '\n');
			obstack_1grow(&stk, 0);
			debug(2,("got : %s", ptr));
			ptr = obstack_finish(&stk);
			found = compare(ptr);
		}
		obstack_free(&stk, NULL);
		
		if (ferror(fp)) {
			/*
			 * Assume that whatever it was set errno...
			 */
			logit(L_ERR|L_PERROR, "finger");
		}
		fclose(fp);
	}
	return found;
}
