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

#ifndef SYSDEP_H_INCLUDED
#define SYSDEP_H_INCLUDED

#if defined(__alpha) && (defined(__osf__) || defined(__linux__))
typedef unsigned int	UINT4;
#else
typedef unsigned long	UINT4;
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#else
# include <string.h>
#endif

#ifndef HAVE_BZERO
# define bzero(s,n) memset(s, 0, n)
#endif

#ifndef HAVE_STRNCASECMP
extern int strncasecmp(char*, char*, int);
#endif

#ifdef TM_IN_SYS_TIME
# include <sys/time.h>
#else
# include <time.h>
#endif

#if defined(bsdi)
# include <machine/inline.h>
# include <machine/endian.h>
#else	/* bsdi */
# ifdef __FreeBSD__
#  include <stdlib.h>
# else
#  include <malloc.h>
# endif  /* FreeBSD */
#endif	/* bsdi */

#if defined(aix)
# include <sys/select.h>
#endif	/* aix 	*/

/* UTMP stuff. Uses utmpx on svr4 */
#ifdef __svr4__
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
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(bsdi)
#  ifndef UTMP_FILE
#    define UTMP_FILE "/var/run/utmp"
#  endif
#  define ut_user ut_name
#endif

#endif /* SYSDEP_H_INCLUDED */
