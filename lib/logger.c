/* This file is part of GNU RADIUS.
   Copyright (C) 2000, 2001, Sergey Poznyakoff
  
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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <varargs.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radius.h>

/*PRINTFLIKE2*/
void
radlog(lvl, msg, va_alist)
        int lvl;
        char *msg;
        va_dcl
{
        va_list ap;
        int ec = 0;

        if (lvl & L_PERROR)
                ec = errno;
        va_start(ap);
        vlog(lvl, NULL, 0, NULL, ec, msg, ap);
        va_end(ap);
}

void
_dolog(level, file, line, func_name, fmt, va_alist)
        int level;
        char *file;
        int line;
        char *func_name;
        char *fmt;
        va_dcl
{
        va_list ap;
        int ec = 0;
        
        if (level & L_PERROR)
                ec = errno;
        va_start(ap);
        vlog(level, file, line, func_name, ec, fmt, ap);
        va_end(ap);
}

void
_debug_print(file, line, func_name, str)
        char *file;
        int line;
        char *func_name;
        char *str;
{
        _dolog(L_DEBUG, file, line, func_name, "%s", str);
        free(str);
}

char *
_debug_format_string(va_alist)
        va_dcl
{
        va_list ap;
        char *fmt;
        char *str = NULL;
        
        va_start(ap);
        fmt = va_arg(ap,char*);
        vasprintf(&str, fmt, ap);
        va_end(ap);
        return str;
}
