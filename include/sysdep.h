/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef SYSDEP_H_INCLUDED
#define SYSDEP_H_INCLUDED

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#include <string.h>

/*FIXME
#ifndef HAVE_STRCHR
# define strchr index
# define strrchr rindex
#endif
#ifndef HAVE_MEMCPY
# define memcpy(d, s, n) bcopy ((s), (d), (n))
# define memmove(d, s, n) bcopy ((s), (d), (n))
#endif
*/
#ifndef HAVE_BZERO
# define bzero(s,n) memset(s, 0, n)
#endif

#if STDC_HEADERS
# include <stdarg.h>
# define __PVAR(c) c
#else
# include <varargs.h>
# define __PVAR(c) 
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
# ifdef TIME_WITH_SYS_TIME
#  include <time.h>
# endif
#else
# include <time.h>
#endif

#ifndef timercmp
#define       timercmp(tvp, uvp, cmp)\
                      ((tvp)->tv_sec cmp (uvp)->tv_sec ||\
                      (tvp)->tv_sec == (uvp)->tv_sec &&\
                      (tvp)->tv_usec cmp (uvp)->tv_usec)
#endif

#if !HAVE_DECL_STRNCASECMP
extern int strncasecmp(char*, char*, int);
#endif

#if !HAVE_DECL_STRTOK_R
extern char *strtok_r(char *s, const char *delim, char **save_ptr);
#endif

#if !HAVE_DECL_LOCALTIME_R
extern struct tm *localtime_r(const time_t *timep, struct tm *res);
#endif

#if !HAVE_DECL_ASPRINTF
int asprintf(/*char **result, const char *format, ...*/);
#endif

#if !HAVE_DECL_VASPRINTF
int vasprintf(char **result, const char *format, va_list args);
#endif

int set_nonblocking(int fd);
int getmaxfd();

#if defined(__alpha) && (defined(__osf__) || defined(__linux__))
typedef unsigned int    UINT4;
#else
typedef unsigned long   UINT4;
#endif

typedef unsigned long counter;

RETSIGTYPE (*install_signal(int signo, void (*func)(int)))(int);
	
#endif /* SYSDEP_H_INCLUDED */

