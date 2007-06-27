/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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

#ifndef HAVE_BZERO
# define bzero(s,n) memset(s, 0, n)
#endif

#include <stdarg.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
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
#ifndef timersub
# define timersub(a, b, result)                             \
  do {                                                      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
    if ((result)->tv_usec < 0) {                            \
      --(result)->tv_sec;                                   \
      (result)->tv_usec += 1000000;                         \
    }                                                       \
  } while (0)
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
int asprintf(char **result, const char *format, ...);
#endif

#if !HAVE_DECL_VASPRINTF
int vasprintf(char **result, const char *format, va_list args);
#endif

#if !HAVE_DECL_CRYPT
extern char *crypt(const char *key, const char *salt);
#endif

typedef RETSIGTYPE (*grad_signal_handler_t)(int);

grad_signal_handler_t grad_set_signal(int sig, grad_signal_handler_t sighandler);
void grad_reset_signal(int sig, grad_signal_handler_t sighandler);


#endif /* SYSDEP_H_INCLUDED */

