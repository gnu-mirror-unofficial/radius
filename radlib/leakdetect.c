/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#define RADIUS_MODULE_LEAKDETECT_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <mem.h>
#include <log.h>
#include <sysdep.h>

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
xmalloc(size)
	size_t size;
{
	char *p;

	p = malloc(size + EXTRA);

	debug(10, ("malloc(%d) = %p", size, p));
	
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
xrealloc(ptr, size)
	void *ptr;
	size_t size;
{
	if (!ptr)
		return xmalloc(size);
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
emalloc(size)
	size_t size;
{
	char *p;

	p = xmalloc(size);
	if (!p) {
		radlog(L_CRIT, _("low core: aborting"));
		abort();
	} 
	return p;
}

void *
erealloc(ptr, size)
	void *ptr;
	size_t size;
{
	ptr = xrealloc(ptr, size);
	if (!ptr) {
		radlog(L_CRIT, _("low core: aborting"));
		abort();
	} 
	return ptr;
}

void 
efree(ptr)
	void *ptr;
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
	
	debug(10, ("free(%p) %d bytes", mhdr, mhdr->s.size));
#else
	debug(10, ("free(%p)", ptr));
#endif
	free(ptr);
}

char *
estrdup(s)
	char *s;
{
	char *p;
	
	if (!s)
		return NULL;
	p = emalloc(strlen(s)+1);
	return strcpy(p, s);
}
