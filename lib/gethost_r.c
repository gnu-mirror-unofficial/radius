/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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
#include <netdb.h>
#include <string.h>

LOCK_DECLARE(lock)

static int
store_hostent(struct hostent *h_in,
	      struct hostent *h_out,
	      char *buf,
	      int buflen,
	      int *h_errnop)
{
        int len, i;
        char *base;
        char **ptr;
        
        if (!buf || !h_errnop)
                return -1;
        *h_errnop = h_errno;
        *h_out = *h_in;

        len = strlen(h_in->h_name) + 1;
        /* Count the aliases */
        len += sizeof(char*);
        for (i = 0; h_in->h_aliases[i]; i++) 
                len += sizeof(char*) + strlen(h_in->h_aliases[i]) + 1;
        base = buf + (i + 1) * sizeof(char*);
#if defined(HAVE_HOSTENT_H_ADDR_LIST) 
        len += sizeof(char*);
        for (i = 0; h_in->h_addr_list[i]; i++)
                len += h_in->h_length + sizeof(char*);
        base += (i + 1) * sizeof(char*);
#else
        len += sizeof (char*) + strlen (h_in->h_addr) + 1;
        base += sizeof(char*);
#endif
        if (len > buflen)
                return -1;

        /* To make sure everything is aligned properly, we store pointers
           first. The variable-length data goes after the pointers; */

        ptr = (char**)buf;
#if defined(HAVE_HOSTENT_H_ADDR_LIST)
        h_out->h_addr_list = ptr;
        /* Store addrlist */
        for (i = 0; h_in->h_addr_list[i]; i++) {
                memcpy(base, h_in->h_addr_list[i], h_in->h_length);
                *ptr++ = base;
                base += h_in->h_length;
        }
        *ptr++ = NULL;
#else
        h_in->h_addr = buf;
        memcpy(h_in->h_addr, h_out->h_addr, h_in->h_length);
        buf += h_in->h_length;
#endif  

        h_out->h_aliases = ptr;
        /* Store aliases */
        for (i = 0; h_in->h_aliases[i]; i++) {
                len = strlen (h_in->h_aliases[i]) + 1;
                memcpy(base, h_in->h_aliases[i], len);
                *ptr++ = base;
                base += len;
        }
        *ptr++ = NULL;
                
        /* Store the h_name */
        h_out->h_name = base;
        len = strlen(h_in->h_name) + 1;
        memcpy(h_out->h_name, h_in->h_name, len);
        return 0;
}
        
struct hostent *
grad_gethostbyname_r(const char *name,
		    struct hostent *result,
		    char *buffer,
		    int buflen,
		    int *h_errnop)
{
        struct hostent *host;

        LOCK_SET(lock)
        host = gethostbyname(name);
        if (!host || store_hostent(host, result, buffer, buflen, h_errnop))
                result = NULL;
        LOCK_RELEASE(lock)
        return result;
}

struct hostent *
grad_gethostbyaddr_r(const char *addr,
		    int length,
		    int type,
		    struct hostent *result,
		    char *buffer,
		    int buflen,
		    int *h_errnop)
{
        struct hostent *host;

        LOCK_SET(lock);
        host = gethostbyaddr (addr, length, type);
        if (!host || store_hostent(host, result, buffer, buflen, h_errnop))
                result = NULL;
        LOCK_RELEASE(lock);
        return result;
}


