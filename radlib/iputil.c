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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <radius.h>


int do_not_resolve = 0;

/*
 *	Return a printable host name (or IP address in dot notation)
 *	for the supplied IP address.
 */
char * 
ip_hostname(ipaddr, namebuf, size)
	UINT4 ipaddr;
	char *namebuf;
	size_t size;
{
	struct hostent *hp, hent;
	char buffer[512];
	UINT4 n_ipaddr;
	int h_err, len;
	
	n_ipaddr = htonl(ipaddr);
	hp = (struct hostent *) NULL;
	if (do_not_resolve == 0) 
		hp = gethostbyaddr_r((char *)&n_ipaddr,
				     sizeof (struct in_addr), AF_INET,
				     &hent, buffer, sizeof buffer, &h_err);
	if (hp == (struct hostent *) NULL) 
		return ipaddr2str(ipaddr, namebuf);

	len = strlen((char *)hp->h_name);
	if (len > size)
		len = size - 1;
	memcpy(namebuf, (char *)hp->h_name, len);
	namebuf[len] = 0;
	return namebuf;
}

/*
 * Return an IP address in host long notation from a host
 * name or address in dot notation.
 */
UINT4 
get_ipaddr(host)
	char *host;
{
	struct hostent	*hp, hent;
	char buffer[512];
	int h_err;
	
	if (good_ipaddr(host) == 0) {
		return ipstr2long(host);
	}
	hp = gethostbyname_r(host, &hent, buffer, sizeof(buffer), &h_err);
	if (!hp)
		return 0;
	return ntohl(*(UINT4 *)hp->h_addr);
}

/*
 * Check for valid IP address in standard dot notation.
 */
int 
good_ipaddr(addr)
	char *addr;
{
	int	dot_count;
	int	digit_count;

	dot_count = 0;
	digit_count = 0;
	while (*addr != 0 && *addr != ' ') {
		if (*addr == '.') {
			if (++dot_count > 3)
				break;
			digit_count = 0;
		} else if (!(isdigit(*addr) && ++digit_count <= 3)) {
			return -1;
		}
		addr++;
	}

	return (dot_count != 3);
}

/*
 * Return an IP address in standard dot notation for the
 * provided address in host long notation.
 */
char *
ipaddr2str(ipaddr, buffer)
	UINT4 ipaddr;
	char *buffer; 
#ifdef HAVE_INET_NTOA
{
	struct in_addr in;
	char           *p;

	in.s_addr = ntohl(ipaddr);
	if (p = inet_ntoa(in))
		strncpy(buffer, p, DOTTED_QUAD_LEN);
	else
		strcpy(buffer, "0.0.0.0");
	return buffer;
}
#else
{
	int	addr_byte[4];
	int	i;
	UINT4	xbyte;

	for (i = 0; i < 4; i++) {
		xbyte = ipaddr >> (i*8);
		xbyte = xbyte & (UINT4)0x000000FF;
		addr_byte[i] = xbyte;
	}
	sprintf(buffer, "%u.%u.%u.%u", addr_byte[3], addr_byte[2],
		addr_byte[1], addr_byte[0]);
	return buffer;
}
#endif

/*
 *	Return an IP address in host long notation from
 *	one supplied in standard dot notation.
 */
UINT4 
ipstr2long(ip_str)
	char *ip_str;
#ifdef HAVE_INET_ATON
{
	struct in_addr in;

	if (inet_aton(ip_str, &in))
		return ntohl(in.s_addr);
	return 0;
}
#else
{
	char	buf[6];
	char	*ptr;
	int	i;
	int	count;
	UINT4	ipaddr;
	int	cur_byte;

	ipaddr = (UINT4)0;
	for (i = 0; i < 4; i++) {
		ptr = buf;
		count = 0;
		*ptr = '\0';
		while (*ip_str != '.' && *ip_str != '\0' && count < 4) {
			if (!isdigit(*ip_str)) {
				return((UINT4)0);
			}
			*ptr++ = *ip_str++;
			count++;
		}
		if (count >= 4 || count == 0) {
			return((UINT4)0);
		}
		*ptr = '\0';
		cur_byte = atoi(buf);
		if (cur_byte < 0 || cur_byte > 255) {
			return((UINT4)0);
		}
		ip_str++;
		ipaddr = ipaddr << 8 | (UINT4)cur_byte;
	}
	return ipaddr;
}
#endif



