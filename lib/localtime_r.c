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

#include <time.h>
#include <pthread.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct tm *
localtime_r(timep, res)
        const time_t *timep;
        struct tm *res;
{
        struct tm *tm;

	pthread_cleanup_push((void (*)(void*))pthread_mutex_unlock, &mutex);
        pthread_mutex_lock(&mutex);
        tm = localtime(timep);
        memcpy(res, tm, sizeof(*res));
        pthread_cleanup_pop(1);
        return res;
}
