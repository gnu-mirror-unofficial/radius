/* This file is part of GNU Radius
   Copyright (C) 2001, 2003, Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <strings.h>
#include <ctype.h>

#ifdef TM_IN_SYS_TIME
# include <sys/time.h>
#else
# include <time.h>
#endif

#include <timestr.h>

#ifdef STANDALONE
# undef ALLOC
# undef FREE
#endif

#ifndef ALLOC
# define ALLOC malloc
#endif
#ifndef FREE
# define FREE free
#endif

#define DAYMIN  (24*60)
#define val(x)  (( (x) < '0' || (x) > '9') ? 0 : ((x) - '0'))

static TIMESPAN *
timespan_new(int start, int stop)
{
        TIMESPAN *ts;

        ts = ALLOC(sizeof(*ts));
        ts->next  = NULL;
        ts->start = start;
        ts->stop  = stop;
        return ts;
}

static void
timespan_day(TIMESPAN **ts, int day, int start, int stop)
{
        TIMESPAN *tp, *prev;
        
        if (stop < start) {
                timespan_day(ts, day, start, DAYMIN);
                timespan_day(ts, day % 7, 0, stop);
                return;
        }

        day *= DAYMIN;
        start += day;
        stop  += day;
        
        if (!*ts) {
                *ts = timespan_new(start, stop);
                return;
        }

        /*
         * Let R be the timespan requested and F the timespan found
         * a. R lies entirely within F.
         *        just return
         * b. R complements F
         *        Append R to F
         * c. R precedes F
         *        insert R before F
         * d. F precedes R
         *        continue
         */
        prev = NULL;
        for (tp = *ts; tp && tp->stop < start; tp = tp->next)
                prev = tp;

        if (tp) {
                if (tp->start <= start && stop <= tp->stop)
                        return;
        
                if (tp->start == stop) {
                        tp->start = start;
                        return;
                }

                if (tp->stop == start) {
                        tp->stop = stop;
                        return;
		}
        }

        tp = timespan_new(start, stop);
        if (prev) {
                tp->next = prev->next;
                prev->next = tp;
        } else {
                tp->next = *ts;
                *ts = tp;
        }
}

static int
timespan_parse(TIMESPAN **ts, char *s, char **endp)
{
        register int i, j;
        register char *p;
        int start, stop;
        char t[3];
        static char *days[] =
        { "su", "mo", "tu", "we", "th", "fr", "sa", "wk", "any", "al" };
        #define ND sizeof(days)/sizeof(days[0])

        for (i = 0; i < sizeof(t); i++)
                t[i] = tolower(s[i]);

        for (i = 0; i < ND; i++) {
                p = days[i];
                for (j = 0; p[j] && p[j] == t[j]; j++)
                        ;
                if (p[j] == 0) {
                        s += j;
                        break;
                }
        }
        if (i == ND) {
                *endp = s;
                return -1;
        }

        /*
         * i is the day of week.
         */
        if (*s && *s != ',' && *s != '|') {
                /* Syntax check */
                p = s;
                for (j = 0; j < 4; j++, p++)
                        if (!isdigit(*p)) {
                                *endp = p;
                                return -1;
                        }
                if (*p != '-') {
                        *endp = p;
                        return -1;
                }
                for (p++, j = 0; j < 4; j++, p++)
                        if (!isdigit(*p)) {
                                *endp = p;
                                return -1;
                        }
                *endp = p;
                /*
                 * determine start and stop limits
                 */
                start = 600 * val(s[0]) + 60 * val(s[1]) + atoi(s + 2);
                s += 5;
                stop  = 600 * val(s[0]) + 60 * val(s[1]) + atoi(s + 2);
        } else {
                *endp = s;
                if (i > 7) { /* al and any */
                        *ts = NULL;
                        return 0;
                }
                start = 0;
                stop = DAYMIN;
        }

        /*
         * Create timespans
         */
        if (i <= 6) 
                timespan_day(ts, i, start, stop);
        else if (i == 7) 
                for (i = 1; i <= 5; i++)
                        timespan_day(ts, i, start, stop);
        else 
                for (i = 0; i <= 6; i++)
                        timespan_day(ts, i, start, stop);

        return 0;
}

void
ts_free(TIMESPAN *sp)
{
        TIMESPAN *next;

        while (sp) {
                next = sp->next;
                FREE(sp);
                sp = next;
        }
}


int
ts_parse(TIMESPAN **sp, char *str, char **endp)
{
        *sp = NULL;
        while (1) {
                if (timespan_parse(sp, str, endp)) {
                        ts_free(*sp);
                        return -1;
                }
                str = *endp;
                if (*str == 0)
                        break;
                if (*str != ',' && *str != '|') {
                        ts_free(*sp);
                        return -1;
                }
                str++;
        }
        return 0;
}

int
ts_match(TIMESPAN *timespan, time_t *time_now, unsigned *rest)
{
        TIMESPAN *tp;
        struct tm *tm, tms;
        unsigned now;
        
        if (!timespan) {
                return 2;
        }

        tm = localtime_r(time_now, &tms);
        now = tm->tm_wday * DAYMIN + tm->tm_hour * 60 + tm->tm_min;

        for (tp = timespan; tp; tp = tp->next) {
                if (tp->start <= now && now < tp->stop) {
                        if (rest)
                                *rest = (tp->stop - now)*60;
                        return 0;
                }
        }

        if (!rest)
                return 1;
        
        for (tp = timespan; tp && tp->stop <= now; tp = tp->next)
                ;
        if (!tp)
                tp = timespan;
        if (tp->start < now)
                *rest = (7*DAYMIN + tp->start - now)*60;
        else
                *rest = (tp->start - now)*60;
        return 1;
}

int
ts_check(char *str, time_t *time, unsigned *rest, char **endp)
{
        TIMESPAN *ts;
        int rc;
        
        if (ts_parse(&ts, str, &str)) {
                if (endp)
                        *endp = str;
                return -1;
        }
        rc = ts_match(ts, time, rest);
        ts_free(ts);
        return rc;
}

#ifdef STANDALONE
int main(int argc, char **argv)
{
        int             l;
        time_t          t;
        TIMESPAN       *ts;
        char           *p;
        unsigned       rest;
        int i;
        struct tm tm;

        time(&t);
        localtime_r(&t, &tm);
        
        switch (argc) {
        default:
                fprintf(stderr, "Usage: %s timestring [dow hh mm]\n",
                        argv[0]);
                exit(1);
        case 5:
                tm.tm_min = atoi(argv[4]);
        case 4:
                tm.tm_hour = atoi(argv[3]);
        case 3:
                tm.tm_wday = 0;
                tm.tm_mday += atoi(argv[2]);
                tm.tm_yday += atoi(argv[2]);
                t = mktime(&tm);
                break;
        case 2:
                break;
        }

        printf("ctime: %s", ctime(&t));
        
        if (ts_parse(&ts, argv[1], &p)) {
                printf("bad timestring near %s\n", p);
                return 1;
        }

        l = ts_match(ts, &t, &rest);
        if (l == 0)
                printf("inside %s: %d seconds left\n", argv[1], rest);
        else
                printf("OUTSIDE %s: %d seconds to wait\n", argv[1], rest);
        return 0;
}
#endif
