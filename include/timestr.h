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
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

typedef struct timespan TIMESPAN;

struct timespan {
        TIMESPAN *next;
        int      start;
        int      stop;
};

void ts_free(TIMESPAN *sp);
int ts_parse(TIMESPAN **sp, char *str, char **endp);
int ts_match(TIMESPAN *timespan, time_t *time_now, unsigned *rest);
int ts_check(char *str, time_t *time, unsigned *rest, char **endp);

#include <radius/mem.h>
#define ALLOC grad_emalloc
#define FREE grad_free
