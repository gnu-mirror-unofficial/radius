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
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <radiusd.h>

#ifdef USE_SNMP

/* ************************************************************************* */
/* Shared memory interface */

static int statfile_perms = S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP;
static int tempfd = -1;
static unsigned offset;
static char *shmem_base;
static unsigned shmem_size;

#ifndef MAP_FAILED
# define MAP_FAILED (void*)-1
#endif

int
shmem_alloc(size_t size)
{
	struct stat sb;
	int init = 0;

	if (tempfd == -1) {
		tempfd = open(grad_stat_file, O_RDWR);
		if (tempfd == -1) {
			if (errno == ENOENT) 
				tempfd = open(grad_stat_file,
					      O_RDWR|O_CREAT|O_TRUNC,
					      statfile_perms);
			
			if (tempfd == -1) {
				grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
					 _("can't open file `%s'"),
				         grad_stat_file);
				return -1;
			}
		}
		if (fstat(tempfd, &sb)) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("can't stat `%s'"),
			         grad_stat_file);
			close(tempfd);
			return -1;
		}
		if ((sb.st_mode & statfile_perms) != statfile_perms) {
			grad_log(GRAD_LOG_ERR,
			         _("SNMP system disabled: file `%s' has incorrect permissions"),
			       grad_stat_file);
			close(tempfd);
			return -1;
		}
		
		if (sb.st_size < size) {
			int c = 0;
			init = 1;
			lseek(tempfd, size - 1, SEEK_SET);
			write(tempfd, &c, 1);
		} else if (sb.st_size > size)
			init = 1;
	}

	shmem_base = mmap((caddr_t)0, size, PROT_READ|PROT_WRITE, MAP_SHARED,
			  tempfd, 0);
	
	if (shmem_base == MAP_FAILED) {
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("mmap failed"));
		return -1;
	} else {
		shmem_size = size;
		if (init) 
			memset(shmem_base, 0, size);
	}
	return 0;
}

void
shmem_free()
{
	munmap(shmem_base, shmem_size);
	close(tempfd);
	tempfd = -1;
	offset = 0;
}

void *
shmem_get(size_t size, int zero)
{
	void *ptr = NULL;

	if (!shmem_base && shmem_alloc(size))
		return NULL;
	if (shmem_size - offset < size) {
		grad_log(GRAD_LOG_ERR,
		         ngettext("shmem_get(): can't allocate %d byte",
			  	  "shmem_get(): can't allocate %d bytes",
				  size),
		         size);
	} else {
		ptr = shmem_base + offset;
		offset += size;
		if (zero)
			memset(ptr, 0, size);
	}
	return ptr;
}



/* ************************************************************************* */
/* Server and port statistics */

int stat_port_count = 1024;
int stat_nas_count = 512;

extern Server_stat *server_stat;
extern struct radstat radstat;
PORT_STAT *port_stat;
struct nas_stat *nas_stat;

void
stat_init()
{
	struct timeval tv;
	struct timezone tz;
	int init;
	
	if (shmem_alloc(stat_port_count * sizeof(PORT_STAT) +
			sizeof(*server_stat) +
			stat_nas_count * sizeof(struct nas_stat))) {
		grad_log(GRAD_LOG_NOTICE, _("stat_init failed"));
		return;
	}

	server_stat = shmem_get(sizeof(*server_stat), 0);
	init = server_stat->port_count != stat_port_count;
	server_stat->port_count = stat_port_count;
	server_stat->nas_count = stat_nas_count;
	
	port_stat = shmem_get(stat_port_count * sizeof(PORT_STAT), init);

	nas_stat = shmem_get(stat_nas_count * sizeof(struct nas_stat), 1);
	
	gettimeofday(&tv, &tz);
	server_stat->start_time = tv; /* FIXME? */
	server_stat->auth.reset_time = tv;
	server_stat->acct.reset_time = tv;	
	server_stat->auth.status = serv_running;
	server_stat->acct.status = serv_running;
}

void
stat_done()
{
	if (server_stat) {
		shmem_free();
		server_stat = NULL;
	}
}

#define FOR_EACH_PORT(p) \
 for (p = port_stat;  p < port_stat + stat_port_count; p++)

static PORT_STAT *
stat_alloc_port()
{
	PORT_STAT *port;
	
	FOR_EACH_PORT(port) {
		if (port->ip == 0)
			return port;
	}
	return NULL;
}

PORT_STAT *
stat_find_port(grad_nas_t *nas, int port_no)
{
	PORT_STAT *port;

	if (!server_stat)
		return NULL;
	FOR_EACH_PORT(port) {
		if (port->ip == 0)
			break;
		if (grad_ip_in_net_p(&nas->netdef, port->ip)
		    && port->port_no == port_no)
			return port;
	}

	/* Port not found */
	if ((port = stat_alloc_port()) == NULL) {
		grad_log(GRAD_LOG_WARN,
		         _("reached SNMP storage limit for the number of monitored ports: increase max-port-count"));
		return NULL;
	}
	port->ip = nas->netdef.ipaddr;
	port->port_no = port_no;
	
	GRAD_DEBUG1(1, "next offset %d", port - port_stat);

	return port;
}

int
stat_get_port_index(grad_nas_t *nas, int port_no)
{
	PORT_STAT *port;
	
	if (!server_stat)
		return 0;
	FOR_EACH_PORT(port) {
		if (port->ip == 0)
			break;
		if (grad_ip_in_net_p(&nas->netdef, port->ip)
		    && port->port_no == port_no)
			return port - port_stat + 1;
	}
	return 0;
}

int
stat_get_next_port_no(grad_nas_t *nas, int port_no)
{
	PORT_STAT *port;
	int next = stat_port_count;
	
	if (!server_stat)
		return 0;
	FOR_EACH_PORT(port) {
		if (port->ip == 0)
			break;
		if (grad_ip_in_net_p(&nas->netdef, port->ip)
		    && port->port_no > port_no 
		    && port->port_no < next)
			next = port->port_no;
	}
	return (next == stat_port_count) ? 0 : next; 
}

void
stat_update(struct radutmp *ut, int status)
{
	grad_nas_t *nas;
	PORT_STAT *port;
	long dt;
        char ipbuf[GRAD_IPV4_STRING_LENGTH];
	
	if (!server_stat)
		return;
	nas = grad_nas_lookup_ip(ntohl(ut->nas_address));
	if (!nas) {
		grad_log(GRAD_LOG_WARN,
		         _("stat_update(): portno %d: can't find nas for IP %s"),
		         ut->nas_port,
		         grad_ip_iptostr(ntohl(ut->nas_address), ipbuf));
		return;
	}
	if (nas->netdef.ipaddr == 0) /* DEFAULT nas */
		return;
	
	port = stat_find_port(nas, ut->nas_port);
	if (!port) {
		grad_log(GRAD_LOG_WARN,
		         _("stat_update(): port %d not found on NAS %s"),
		         ut->nas_port,
		         grad_ip_iptostr(ntohl(ut->nas_address), ipbuf));
		return;
	}

	switch (status) {
	case DV_ACCT_STATUS_TYPE_START:
		if (port->start) {
			dt = ut->time - port->start;
			if (dt < 0) {
                                grad_log(GRAD_LOG_NOTICE,
				         "stat_update(START,%s,%s,%d): %s",
				         ut->login, nas->shortname, ut->nas_port,
				         _("negative port idle time"));
			} else {
				port->idle += dt;
			}
			if (dt > port->maxidle.time) {
				port->maxidle.time = dt;
				port->maxidle.start = port->start;
			}
		}
		
		strncpy(port->login, ut->login, sizeof(port->login));
		port->framed_address = ut->framed_address;
		port->active = 1;
		port->count++;
		port->start = port->lastin = ut->time;
		break;
		
	case DV_ACCT_STATUS_TYPE_STOP:
		if (port->start) {
			dt = ut->time - port->start;
			if (dt < 0) {
                                grad_log(GRAD_LOG_NOTICE,
				       "stat_update(STOP,%s,%s,%d): %s",
				       ut->login, nas->shortname, ut->nas_port,
				       _("negative port session time"));
			} else {
				port->inuse += dt;
			}
			if (dt > port->maxinuse.time) {
				port->maxinuse.time = dt;
				port->maxinuse.start = port->start;
			}
		}
		
		port->active = 0;
		port->start = port->lastout = ut->time;
		break;

	case DV_ACCT_STATUS_TYPE_ALIVE:
		strncpy(port->login, ut->login, sizeof(port->login));
		port->framed_address = ut->framed_address;
		port->active = 1;
		break;
	}

	GRAD_DEBUG9(1,
		"NAS %#x port %d: act %d, cnt %d, start %d, inuse %d/%d idle %d/%d",
		port->ip, port->port_no, port->active,
		port->count, port->start,
		port->inuse, port->maxinuse.time,
		port->idle, port->maxidle.time);
}

void
stat_count_ports()
{
	grad_nas_t *nas;
	struct nas_stat *statp;
	PORT_STAT *port;
	grad_iterator_t *itr;

	if (!server_stat)
		return;
 	itr = grad_nas_iterator();	
	for (nas = grad_iterator_first(itr); nas; nas = grad_iterator_next(itr)) {
		statp = nas->app_data;
		statp->ports_active = statp->ports_idle = 0;
	}
	grad_iterator_destroy(&itr);
	
	radstat.port_active_count = radstat.port_idle_count = 0;

	FOR_EACH_PORT(port) {
		if (port->ip == 0)
			break;

		nas = grad_nas_lookup_ip(port->ip);
		if (!nas) {
			/* Silently ignore */
			continue;
		}
		statp = nas->app_data;
		if (port->active) {
			statp->ports_active++;
			radstat.port_active_count++;
		} else {
			statp->ports_idle++;
			radstat.port_idle_count++;
		}
	}
}

PORT_STAT *
findportbyindex(int ind)
{
	PORT_STAT *p;
	int i;

	if (!server_stat
	    || ind < 1
	    || ind > stat_port_count)
                return NULL;
	i = 1;
	FOR_EACH_PORT(p) {
		if (i == ind || p->ip == 0)
			break;
		i++;
	}
	if (p->ip == 0)
		return NULL;
	return p;
}


/* ************************************************************************* */
/* NAS statistics */

#define FOR_EACH_NAS(n) \
 for (n = nas_stat; n < nas_stat + stat_nas_count; n++)

void
snmp_init_nas_stat()
{
	if (!server_stat)
		return;
        server_stat->nas_index = 0;
}

/* For a given ip_address return NAS statistics info associated with it.
   if no NAS with this address is known, return NULL */
struct nas_stat *
find_nas_stat(grad_uint32_t ip_addr)
{
        struct nas_stat *np;

	if (!server_stat)
		return NULL;
	FOR_EACH_NAS(np) {
                if (np->ipaddr == ip_addr)
                        return np;
	}
        return NULL;
}

/* Attach NAS stat info to a given NAS structure. */
void
snmp_attach_nas_stat(grad_nas_t *nas)
{
        struct nas_stat *np;

	if (!server_stat)
		return;
        np = find_nas_stat(nas->netdef.ipaddr); 
        if (!np) {
		if (server_stat->nas_index >= server_stat->nas_count) {
			grad_log(GRAD_LOG_WARN,
			         _("reached SNMP storage limit for the number of monitored NASes: increase max-nas-count"));
			return;
		}
		np = nas_stat + server_stat->nas_index;
		++server_stat->nas_index;
                np->ipaddr = nas->netdef.ipaddr;
        }
        nas->app_data = np;
}

static int
nas_ip_cmp(const void *ap, const void *bp)
{
        const struct nas_stat *a = ap, *b = bp;
        return a->ipaddr - b->ipaddr;
}

void
snmp_sort_nas_stat()
{
        struct nas_stat *np;
        int i;

	if (!server_stat)
		return;
        qsort(nas_stat, server_stat->nas_index + 1,
              sizeof(struct nas_stat*), nas_ip_cmp);
	i = 1;
	FOR_EACH_NAS(np) {
                np->index = i++;
	}
}


/* ************************************************************************* */
/* Configuration */
static int
stat_cfg_file(int argc, cfg_value_t *argv,
	      void *block_data ARG_UNUSED, void *handler_data ARG_UNUSED)
{
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	grad_free(grad_stat_file);
	if (argv[1].v.string[0] != '/')
		grad_stat_file = grad_estrdup(argv[1].v.string);
	else
		grad_stat_file = grad_mkfilename(grad_log_dir, argv[1].v.string); 
	
	return 0;
}

struct cfg_stmt storage_stmt[] = {
	{ "file", CS_STMT, NULL, stat_cfg_file, NULL, NULL, NULL },
	{ "perms", CS_STMT, NULL, cfg_get_integer, &statfile_perms, NULL, NULL },
	{ "max-port-count", CS_STMT, NULL,
	  cfg_get_integer, &stat_port_count, NULL, NULL },
	{ "max-nas-count", CS_STMT, NULL,
	  cfg_get_integer, &stat_nas_count, NULL, NULL },
	{ NULL, }
};

#endif
