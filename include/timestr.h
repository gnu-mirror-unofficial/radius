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

#include <mem.h>
#define ALLOC mem_alloc
#define FREE mem_free
