/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_LEAKDETECT_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <mem.h>
#include <radius.h>

#ifdef LEAK_DETECTOR
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
radxmalloc(size_t size)
{
        char *p;

        p = malloc(size + EXTRA);

	if (debug_on(10)) 
		printf("malloc(%d) = %p\n", size, p);
        
        if (p) {
#ifdef LEAK_DETECTOR
                MHDR *mhdr;
                
                mallocstat.size += size;
                mallocstat.count++;

                mhdr = (MHDR*)p;
                mhdr->s.size = size;
                p += EXTRA;
#endif
                bzero(p, size);
        }
        return p;
}

void *
radxrealloc(void *ptr, size_t size)
{
        if (!ptr)
                return radxmalloc(size);
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
#else
                ptr = realloc(ptr, size);
#endif
        }
        return ptr;
}

void *
emalloc(size_t size)
{
        char *p;

        p = radxmalloc(size);
        if (!p) {
                radlog(L_CRIT, _("low core: aborting"));
                abort();
        } 
        return p;
}

void *
erealloc(void *ptr, size_t size)
{
        ptr = radxrealloc(ptr, size);
        if (!ptr) {
                radlog(L_CRIT, _("low core: aborting"));
                abort();
        } 
        return ptr;
}

void 
efree(void *ptr)
{
#ifdef LEAK_DETECTOR
        MHDR *mhdr;
#endif

        if (!ptr)
                return;

#ifdef LEAK_DETECTOR
        ptr = (char*)ptr - EXTRA;
        mhdr = (MHDR*)ptr;

        mallocstat.size -= mhdr->s.size;
        mallocstat.count--;
        
        if (debug_on(10))
		printf("free(%p) %d bytes\n", mhdr, mhdr->s.size);
#else
        if (debug_on(10))
		printf("free(%p)\n", ptr);
#endif
        free(ptr);
}

char *
estrdup(char *s)
{
        char *p;
        
        if (!s)
                return NULL;
        p = emalloc(strlen(s)+1);
        return strcpy(p, s);
}

char *
string_replace(char **str, char *new_value)
{
	char *p = *str;
	*str = estrdup(new_value);
	if (p)
		efree(p);
	return *str;
}
