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

#ifndef SYSDEP_H_INCLUDED
#define SYSDEP_H_INCLUDED

#if defined(__alpha) && (defined(__osf__) || defined(__linux__))
typedef unsigned int	UINT4;
#else
typedef unsigned long	UINT4;
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#include <string.h>

#ifndef HAVE_BZERO
# define bzero(s,n) memset(s, 0, n)
#endif

#ifndef HAVE_STRNCASECMP
extern int strncasecmp(char*, char*, int);
#endif

#ifndef HAVE_STRTOK_R
extern char *strtok_r (char *s, const char *delim, char **save_ptr);
#endif

#ifndef HAVE_LOCALTIME_R
extern struct tm *localtime_r(const time_t *timep, struct tm *res);
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
# ifdef TIME_WITH_SYS_TIME
#  include <time.h>
# endif
#else
# include <time.h>
#endif

#if defined(bsdi)
# include <machine/inline.h>
# include <machine/endian.h>
#else	/* bsdi */
# if defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <stdlib.h>
# else
#  include <malloc.h>
# endif  /* FreeBSD and OpenBSD */
#endif	/* bsdi */

#if defined(HAVE_SYS_SELECT_H)  
# include <sys/select.h>
#endif	/* needed for AIX */

/* UTMP stuff. Uses utmpx on svr4 */
#if defined(__svr4__) || defined(__sgi)  
#  include <utmpx.h>
#  include <sys/fcntl.h>
#  define utmp utmpx
#  define UT_NAMESIZE	32
#  define UT_LINESIZE	32
#  define UT_HOSTSIZE	257
#  undef UTMP_FILE
#  define UTMP_FILE UTMPX_FILE
#  undef WTMP_FILE
#  define WTMP_FILE WTMPX_FILE
#else
#  include <utmp.h>
#endif
#ifdef __osf__
#  define UT_NAMESIZE	32
#  define UT_LINESIZE	32
#  define UT_HOSTSIZE	64
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(bsdi)
#  ifndef UTMP_FILE
#    define UTMP_FILE "/var/run/utmp"
#  endif
#  define ut_user ut_name
#endif

#if defined (sun) && defined(__svr4__)
RETSIGTYPE (*sun_signal(int signo, void (*func)(int)))(int);
#define signal sun_signal
#endif
int set_nonblocking(int fd);
int getmaxfd();

typedef unsigned long counter;

#endif /* SYSDEP_H_INCLUDED */
