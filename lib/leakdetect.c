/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
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
grad_malloc(size_t size)
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

void *
grad_emalloc(size_t size)
{
        char *p;

        p = grad_malloc(size);
        if (!p) {
                grad_log(L_CRIT, _("low core: aborting"));
                abort();
        } 
        return p;
}

void *
grad_erealloc(void *ptr, size_t size)
{
        ptr = grad_realloc(ptr, size);
        if (!ptr) {
                grad_log(L_CRIT, _("low core: aborting"));
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
