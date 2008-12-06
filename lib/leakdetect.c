/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2006,2007,2008 Free Software Foundation, Inc.

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
#include <radlib.h>

#ifdef LEAK_DETECTOR
# if LEAK_DETECTOR > 1

# ifndef MAX_BLOCK_SIZE
#  define MAX_BLOCK_SIZE 4096
# endif

# ifndef MEMORY_CHECK_INTERVAL
#  define MEMORY_CHECK_INTERVAL 5*60
# endif

static size_t nsamples;    /* Number of samples collected */
static time_t last_time;   /* Time the last sample was taken */

/* Memory usage counters. In each array below, Nth element contains
   the number of allocated memory blocks of size N */
static size_t last_counter[MAX_BLOCK_SIZE]; /* The memory usage at last_time */
static size_t counter[MAX_BLOCK_SIZE];      /* Current memory usage */
/* Differences */
static long long diff[MAX_BLOCK_SIZE];      /* Difference between counter and
					       last_counter */
static double mean_diff[MAX_BLOCK_SIZE];    /* Mean speed of memory
					       allocation */
static double mean_acc[MAX_BLOCK_SIZE];     /* Mean acceleration of memory
					       allocation */

static void
dump(time_t t)
{
	FILE *fp;
	char *fname;
	pid_t pid = getpid();
	size_t size, len;
	
	if (!grad_log_dir)
		return;

#define DUMPFILENAME "/radmem."
	
	size = grad_ulongtostr((unsigned long) pid, NULL, 0);
	size += strlen(grad_log_dir) + sizeof DUMPFILENAME;
	fname = malloc(fname);
	if (!fname) {
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("not enough memory"));
		return;
	}
	strcpy(fname, grad_log_dir);
	strcat(fname, DUMPFILENAME);
	len = strlen(fname);
	grad_ulongtostr(pid, fname + len, size - len);

	fp = fopen(fname, "w");
	if (!fp) 
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
		         "cannot open file %s", fname);
	else {
		size_t i;
				
		fprintf(fp, "%lu\t%lu\n", (unsigned long) t, nsamples + 1);
		fprintf(fp, "Size\tCprev\tCnow\tDiff\tMdiff\tMacc\n");
		for (i = 0; i < MAX_BLOCK_SIZE; i++) {
			long long d = (long long)counter[i] - last_counter[i];
			double a = d - diff[i];

			diff[i] = d;
			mean_diff[i] = (double) (nsamples * mean_diff[i] + d)
				           / (nsamples + 1);
			
			mean_acc[i] = (double) (nsamples * mean_acc[i] + a)
				           / (nsamples + 1);
			if (d != 0) {
				fprintf(fp, "%lu\t%lu\t%lu\t%lli\t%7.3f\t%7.3f\n",
					i,
					last_counter[i],
					counter[i],
					d,
					mean_diff[i],
					mean_acc[i]);
			}
		}
		nsamples++;
		fclose(fp);
	}
	memcpy(last_counter, counter, sizeof last_counter);
	free(fname);
}

static void
check_dump()
{
	time_t t = time(NULL);
	if (t - last_time > MEMORY_CHECK_INTERVAL) {
		dump(t);
		last_time = t;
	}
}

#  define INCREASE(s) do {\
	if (s < MAX_BLOCK_SIZE)\
		counter[s]++;\
	check_dump();\
} while (0)

#  define DECREASE(s) do {\
	if (s < MAX_BLOCK_SIZE)\
		counter[s]--;\
	check_dump();\
} while (0)
# else  /* not LEAK_DETECTOR > 1 */
#  define INCREASE(s)
#  define DECREASE(s)
# endif /* LEAK_DETECTOR > 1 */
	   
typedef union mem_header MHDR;
union mem_header {
        struct {
                size_t size;
        } s;
        Align_t align;
};
# define EXTRA sizeof(MHDR)
struct mallocstat mallocstat;
#else
# define EXTRA 0        
#endif

void *
grad_malloc(size_t size)
{
        char *p;

        p = malloc(size + EXTRA);

	GRAD_DEBUG2(10, "malloc(%d) = %p", size, p);
        
        if (p) {
#ifdef LEAK_DETECTOR
                MHDR *mhdr;
                
		INCREASE(size);
                mallocstat.size += size;
                mallocstat.count++;

                mhdr = (MHDR*)p;
                mhdr->s.size = size;
                p += EXTRA;
#endif
                memset(p, 0, size);
        }
        return p;
}

void *
grad_realloc(void *ptr, size_t size)
{
        if (!ptr)
                return grad_malloc(size);
        else {
#ifdef LEAK_DETECTOR
                MHDR *mhdr;
                size_t osize;
                
                mhdr = (MHDR*)((char*)ptr - EXTRA);
                osize = mhdr->s.size;

                ptr = realloc(mhdr, size + EXTRA);
                if (ptr) {
                        mhdr = (MHDR*)ptr;
                        mhdr->s.size = size;
                        mallocstat.size += size - osize;
                        ptr = (char*)ptr + EXTRA;
                }
		DECREASE(osize);
		INCREASE(size);
#else
                ptr = realloc(ptr, size);
#endif
        }
        return ptr;
}

void 
grad_free(void *ptr)
{
#ifdef LEAK_DETECTOR
        MHDR *mhdr;
#endif

        if (!ptr)
                return;

#ifdef LEAK_DETECTOR
        ptr = (char*)ptr - EXTRA;
        mhdr = (MHDR*)ptr;

	DECREASE(mhdr->s.size);
        mallocstat.size -= mhdr->s.size;
        mallocstat.count--;
        
        GRAD_DEBUG2(10, "free(%p) %d bytes", mhdr, mhdr->s.size);
#else
        GRAD_DEBUG1(10, "free(%p)", ptr);
#endif
        free(ptr);
}

void
grad_destroy(void **pptr)
{
	if (*pptr) {
		grad_free(*pptr);
		*pptr = NULL;
	}
}

void *
grad_emalloc(size_t size)
{
        char *p;

        p = grad_malloc(size);
        if (!p) {
                grad_log(GRAD_LOG_CRIT, _("low core: aborting"));
                abort();
        } 
        return p;
}

void *
grad_erealloc(void *ptr, size_t size)
{
        ptr = grad_realloc(ptr, size);
        if (!ptr) {
                grad_log(GRAD_LOG_CRIT, _("low core: aborting"));
                abort();
        } 
        return ptr;
}

char *
grad_estrdup(const char *s)
{
        char *p;
        
        if (!s)
                return NULL;
        p = grad_emalloc(strlen(s)+1);
        return strcpy(p, s);
}

char *
grad_string_replace(char **str, const char *new_value)
{
	char *p = *str;
	*str = grad_estrdup(new_value);
	if (p)
		grad_free(p);
	return *str;
}
