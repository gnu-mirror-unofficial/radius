/* This file is part of GNU RADIUS.
   Copyright (C) 2001, Sergey Poznyakoff
  
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
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

#include <radius.h>

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
set_nonblocking(fd)
        int fd;
{
        int flags;

        if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
                radlog(L_ERR|L_PERROR, "F_GETFL");
                return -1;
        }
        if (fcntl(fd, F_SETFL, flags | FCNTL_NONBLOCK) < 0) {
                radlog(L_ERR|L_PERROR, "F_GETFL");
                return -1;
        }
        return 0;
}

RETSIGTYPE
(*install_signal_flags(signo, func, flags))(int)
        int signo;
        void (*func)(int);
	int flags;
{
	struct sigaction act, oact;
		
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = flags;
#ifdef  SA_INTERRUPT            /* SunOS */
        act.sa_flags |= SA_INTERRUPT;
#endif
        if (sigaction(signo, &act, &oact) < 0)
                return SIG_ERR;
        return oact.sa_handler;
}

RETSIGTYPE
(*install_signal(signo, func))(int)
        int signo;
        void (*func)(int);
{
	return install_signal_flags(signo, func, SA_RESTART);
}

#define DEFMAXFD 512

/*
 * Return maximum number of file descriptors available
 */
int
getmaxfd()
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
                
