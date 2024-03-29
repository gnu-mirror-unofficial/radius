/* GNU Mailutils -- a suite of utilities for electronic mail
   Copyright (C) 1999, 2000, 2001, 2005, 2007, 2010, 2013 Free Software
   Foundation, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. */

#ifndef _ARGCV_H
#define _ARGCV_H 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __P
# if defined PROTOTYPES || (defined __STDC__ && __STDC__)
#  define __P(args) args
# else
#  define __P(args) ()
# endif
#endif /*__P */

extern int grad_argcv_get    __P ((const char *command, const char *delim,
			      const char* cmnt,
			      int *argc, char ***argv));
extern int grad_argcv_string __P ((int argc, char **argv, char **string));
extern int grad_argcv_free   __P ((int argc, char **argv));
extern int grad_argcv_unquote_char __P((int c));
extern int grad_argcv_quote_char __P((int c));
extern size_t grad_argcv_quoted_length __P((const char *str, int *quote));
extern size_t grad_argcv_quoted_length_n __P((const char *str, size_t size,
					      int *quote));
extern void grad_argcv_unquote_copy __P((char *dst, const char *src,
					 size_t n));
extern void grad_argcv_quote_copy_n __P((char *dst, const char *src,
					 size_t size));
extern void grad_argcv_quote_copy __P((char *dst, const char *src));

#ifdef __cplusplus
}
#endif

#endif /* _ARGCV_H */
