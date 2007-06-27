/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007 Free Software Foundation, Inc.

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
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#include <radlib.h>

int grad_resolve_hostnames = 1;

/*
 * Check for valid IP address in standard dot notation.
 */
static int 
good_ipaddr(const char *addr)
{
        int     dot_count;
        int     digit_count;

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
 *      Return a printable host name (or IP address in dot notation)
 *      for the supplied IP address.
 */
char * 
grad_ip_gethostname(grad_uint32_t ipaddr, char *namebuf, size_t size)
{
        struct hostent *hp, hent;
        char buffer[512];
        grad_uint32_t n_ipaddr;
        int h_err, len;
        
        n_ipaddr = htonl(ipaddr);
        hp = (struct hostent *) NULL;
        if (grad_resolve_hostnames) 
                hp = grad_gethostbyaddr_r((char *)&n_ipaddr,
					  sizeof (struct in_addr), AF_INET,
					  &hent, buffer, sizeof buffer,
					  &h_err);
        if (hp == (struct hostent *) NULL) 
                return grad_ip_iptostr(ipaddr, namebuf);

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
grad_uint32_t 
grad_ip_gethostaddr(const char *host)
{
        struct hostent  *hp, hent;
        char buffer[512];
        int h_err;
        
        if (good_ipaddr(host) == 0) {
                return grad_ip_strtoip(host);
        }
        hp = grad_gethostbyname_r(host, &hent, buffer, sizeof(buffer), &h_err);
        if (!hp)
                return 0;
        return ntohl(*(grad_uint32_t *)hp->h_addr);
}

/*
 * Return an IP address in standard dot notation for the
 * provided address in host long notation.
 */
char *
grad_ip_iptostr(grad_uint32_t ipaddr, char *bufp)
{
	static char buffer[GRAD_IPV4_STRING_LENGTH];
	if (!bufp)
		bufp = buffer;
        sprintf(bufp, "%u.%u.%u.%u",
                (u_int) ((ipaddr >> 24) & 0xff),
                (u_int) ((ipaddr >> 16) & 0xff),
                (u_int) ((ipaddr >> 8) & 0xff),
                (u_int) (ipaddr & 0xff));
        return bufp;
}

/*
 *      Return an IP address in host long notation from
 *      one supplied in standard dot notation.
 */
grad_uint32_t 
grad_ip_strtoip(const char *ip_str)
#ifdef HAVE_INET_ATON
{
        struct in_addr in;

        if (inet_aton(ip_str, &in))
                return ntohl(in.s_addr);
        return 0;
}
#else
{
        char    buf[6];
        char    *ptr;
        int     i;
        int     count;
        grad_uint32_t   ipaddr;
        int     cur_byte;

        ipaddr = (grad_uint32_t)0;
        for (i = 0; i < 4; i++) {
                ptr = buf;
                count = 0;
                *ptr = '\0';
                while (*ip_str != '.' && *ip_str != '\0' && count < 4) {
                        if (!isdigit(*ip_str)) {
                                return((grad_uint32_t)0);
                        }
                        *ptr++ = *ip_str++;
                        count++;
                }
                if (count >= 4 || count == 0) {
                        return((grad_uint32_t)0);
                }
                *ptr = '\0';
                cur_byte = atoi(buf);
                if (cur_byte < 0 || cur_byte > 255) {
                        return((grad_uint32_t)0);
                }
                ip_str++;
                ipaddr = ipaddr << 8 | (grad_uint32_t)cur_byte;
        }
        return ipaddr;
}
#endif

int
grad_ip_getnetaddr(const char *str, grad_netdef_t *netdef)
{
	char *p = strchr(str, '/');
	if (!p) {
		netdef->netmask = 0xfffffffful;
		netdef->ipaddr = grad_ip_gethostaddr(str);
	} else {
		char buf[GRAD_IPV4_STRING_LENGTH];
		size_t len = p - str;

		if (len >= GRAD_IPV4_STRING_LENGTH)
			return 1;
		memcpy(buf, str, len);
		buf[len] = 0;
		netdef->ipaddr = grad_ip_strtoip(buf);
					
		if (good_ipaddr(p+1) == 0)
			netdef->netmask = grad_ip_strtoip(p+1);
		else {
			char *endp;
			grad_uint32_t n = strtoul(p+1, &endp, 0);
			if (*endp || n > 32)
				return 1;
			n = 32 - n;
			if (n == 32)
				netdef->netmask = 0;
			else
				netdef->netmask = (0xfffffffful >> n) << n;
		}
		netdef->ipaddr &= netdef->netmask;
	}
	return 0;
}

int
grad_ip_in_net_p(const grad_netdef_t *netdef, grad_uint32_t ipaddr)
{
	return netdef->ipaddr == (ipaddr & netdef->netmask);
}
