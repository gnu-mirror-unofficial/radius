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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <log.h>
#include <mem.h>
#include <sysdep.h>
#include <radiusd.h>
#include <radpaths.h>

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

extern char *radacct_dir;
static int tempfd = -1;
static unsigned offset;
static char *shmem_base;
static unsigned shmem_size;

#define PERM S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP

int
shmem_alloc(size)
	unsigned size;
{
	struct stat sb;
	int init = 0;

	if (tempfd == -1) {
		tempfd = open(radstat_path, O_RDWR);
		if (tempfd == -1) {
			if (errno == ENOENT) 
				tempfd = open(radstat_path,
					      O_RDWR|O_CREAT|O_TRUNC, PERM);
			
			if (tempfd == -1) {
				radlog(L_ERR|L_PERROR, _("can't open file `%s'"),
				    radstat_path);
				return -1;
			}
		}
		if (fstat(tempfd, &sb)) {
			radlog(L_ERR|L_PERROR, _("can't stat `%s'"),
			    radstat_path);
			close(tempfd);
			return -1;
		}
		if (sb.st_size < size) {
			int c = 0;
			init = 1;
			lseek(tempfd, size, SEEK_SET);
			write(tempfd, &c, 1);
		}
	}

	shmem_base = mmap((caddr_t)0, size, PROT_READ|PROT_WRITE, MAP_SHARED,
			  tempfd, 0);
	
	if (!shmem_base) {
		radlog(L_ERR|L_PERROR, _("mmap failed"));
		return -1;
	} else {
		shmem_size = size;
		if (init) 
			bzero(shmem_base, size);
	}
	return 0;
}

void
shmem_free()
{
	munmap(shmem_base, shmem_size);
	close(tempfd);
}

void *
shmem_get(size, zero)
	unsigned size;
        int zero;
{
	void *ptr = NULL;

	if (!shmem_base && shmem_alloc(size))
		return NULL;
	if (shmem_size - offset < size) {
		radlog(L_ERR, _("shmem_get(): can't alloc %d bytes"), size);
	} else {
		ptr = shmem_base + offset;
		offset += size;
		if (zero)
			bzero(ptr, size);
	}
	return ptr;
}
