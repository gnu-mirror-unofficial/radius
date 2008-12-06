/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007,
   2008 Free Software Foundation, Inc.

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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(HAVE_SYS_RESOURCE_H)
# include <sys/resource.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include <radlib.h>

#if defined(O_NONBLOCK)
# define FCNTL_NONBLOCK O_NONBLOCK
#elif defined(O_NDELAY)
# define FCNTL_NONBLOCK O_NDELAY
#else
# error "Neither O_NONBLOCK nor O_NDELAY are defined"
#endif

/*
 * Put a socket on a non-blocking mode
 */
int
grad_set_nonblocking(int fd)
{
        int flags;

        if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "F_GETFL");
                return -1;
        }
        if (fcntl(fd, F_SETFL, flags | FCNTL_NONBLOCK) < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "F_SETFL");
                return -1;
        }
        return 0;
}

#define DEFMAXFD 512

/*
 * Return maximum number of file descriptors available
 */
int
grad_max_fd()
{
#if defined(HAVE_GETDTABLESIZE)
        return getdtablesize();
#elif defined(RLIMIT_NOFILE)
        struct rlimit rlim;

        if (getrlimit(RLIMIT_NOFILE, &rlim)) 
                return DEFMAXFD;
        return rlim.rlim_max;
#else
        return DEFMAXFD;
#endif
}

static grad_uint32_t
grad_first_ip_nameindex()
{
	grad_uint32_t ip = INADDR_ANY;
#ifdef SIOCGIFCONF
	struct ifreq *ifr, *end, *cur;
	struct ifconf ifc;
	struct sockaddr_in *sinp;
	int rq_len, last_len;
	int fd = socket (PF_INET, SOCK_STREAM, 0);
	
	if (fd == -1)
		return INADDR_ANY;
	
	/* A first estimate.  */
	rq_len = 4 * sizeof (struct ifreq);

	ifc.ifc_buf = NULL;
	ifc.ifc_len = 0;

        /* Read all the interfaces out of the kernel.  */
	do {
		last_len = ifc.ifc_len;
		ifc.ifc_buf = malloc(ifc.ifc_len = rq_len);
		if (ifc.ifc_buf == NULL || ioctl (fd, SIOCGIFCONF, &ifc) < 0) {
			free(ifc.ifc_buf);
			close(fd);
			return INADDR_ANY;
		}
		rq_len *= 2;
	} while (ifc.ifc_len != last_len);

	/* Now find first non-loopback address */
	ifr = (struct ifreq *)ifc.ifc_req;
	end = (struct ifreq *)((caddr_t)ifr + ifc.ifc_len);

	while (ifr < end) {
		int len = 0;
#ifdef HAVE_SOCKADDR_SA_LEN
		len = ifr->ifr_addr.sa_len;
#endif
		if (sizeof(struct sockaddr) > len)
			len = sizeof(struct sockaddr);

		cur = ifr;
      
		/* Advance the pointer for the next loop */
		ifr = (struct ifreq *)((caddr_t)ifr + len + IFNAMSIZ);

		sinp = (struct sockaddr_in *)&cur->ifr_addr;
		if (sinp->sin_family == AF_INET) {
			grad_uint32_t n = ntohl(sinp->sin_addr.s_addr);

			if (n != INADDR_LOOPBACK) {
				ip = n;
				break;
			}
		}
	}

	free(ifc.ifc_buf);
	close(fd);
#endif
	return ip;
}

static grad_uint32_t
grad_first_ip_hostname()
{
	grad_uint32_t ip = INADDR_ANY;
	char *name;
	int name_len = 256;
	int status;

	name = grad_emalloc(name_len);
	while (name
	       && (status = gethostname(name, name_len)) == 0
	       && !memchr(name, 0, name_len)) {
		name_len *= 2;
		name = grad_erealloc(name, name_len);
	}
	if (status == 0) 
		ip = grad_ip_gethostaddr(name);
	grad_free(name);
	return ip;
}

grad_uint32_t
grad_first_ip()
{
	grad_uint32_t ip = INADDR_ANY;

	ip = grad_first_ip_nameindex();
	if (ip == INADDR_ANY)
		/* Too bad. Try to use older approach */
		ip = grad_first_ip_hostname();
	
	return ip;
}

#ifdef HAVE_SIGACTION

grad_signal_handler_t
grad_set_signal(int sig, grad_signal_handler_t sighandler)
{
	struct sigaction act, oact;
	
	act.sa_handler = sighandler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
# ifdef  SA_INTERRUPT           
	act.sa_flags |= SA_INTERRUPT;
# endif
	if (sigaction (sig, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
}

void
grad_reset_signal(int sig ARG_UNUSED, grad_signal_handler_t sighandler ARG_UNUSED)
{
}

#else

grad_signal_handler_t
grad_set_signal(int sig, grad_signal_handler_t sighandler)
{
	return signal(sig, sighandler);
}

void
grad_reset_signal(int sig, grad_signal_handler_t sighandler)
{
	grad_set_signal(sig, sighandler);
}
#endif

