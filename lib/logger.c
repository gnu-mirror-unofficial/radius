/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2003,2004,2007,2008 Free Software Foundation, Inc.

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radlib.h>
#include <radargp.h>

#define SP(p) ((p)?(p):"")



static grad_logger_fp _grad_logger = grad_default_logger;

grad_logger_fp
grad_set_logger(grad_logger_fp fp)
{
	grad_logger_fp tmp = _grad_logger;
	_grad_logger = fp;
	return tmp;
}

void
grad_log(int lvl, const char *msg, ...)
{
        va_list ap;
        int ec = 0;

        if (lvl & GRAD_LOG_PERROR)
                ec = errno;
        va_start(ap, msg);
	if (_grad_logger)
		_grad_logger(lvl, NULL, NULL, NULL, ec, msg, ap);
        va_end(ap);
}

void
grad_log_req(int lvl, grad_request_t *req, const char *msg, ...)
{
        va_list ap;
        int ec = 0;

        if (lvl & GRAD_LOG_PERROR)
                ec = errno;
        va_start(ap, msg);
	if (_grad_logger)
		_grad_logger(lvl, req, NULL, NULL, ec, msg, ap);
        va_end(ap);
}

void
grad_log_loc(int lvl, grad_locus_t *loc, const char *msg, ...)
{
	va_list ap;
	int ec = 0;

	if (lvl & GRAD_LOG_PERROR)
		ec = errno;

	va_start(ap, msg);
	if (_grad_logger)
		_grad_logger(lvl, NULL, loc, NULL, ec, msg, ap);
	va_end(ap);
}
