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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#define RADIUS_MODULE_STAT_C
#ifndef lint
static char rcsid[] = 
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/in.h>
#if defined(sun)
# include <fcntl.h>
#endif
#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>

#ifdef USE_SNMP
extern Server_stat server_stat;
extern struct radstat radstat;
static pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Statistics file format:

   struct stat_header +
   Auth_server_stat +
   Acct_server_stat +
   struct nas_stat [...] +
   struct port_stat [...] 
*/

struct stat_header {
        char sign[4];
        unsigned checksum;
        unsigned nas_count;
        unsigned port_count;
        struct timeval start_time;
};

void
update_checksum(sump, data, length)
        unsigned *sump;
        u_char *data;
        int length;
{
        while (length-- > 0) 
                *sump += *data++;
}


int
statfile_verify(fd, hdr, auth, acct)
        int fd;
        struct stat_header *hdr;
        Auth_server_stat *auth;
        Acct_server_stat *acct;
{
        unsigned saved_checksum, checksum = 0;
        u_char *buf;
        unsigned bufsize = 1024;
        long here;
        
        if (read(fd, hdr, sizeof(*hdr)) != sizeof(*hdr))
                return 1;
        saved_checksum = hdr->checksum;
        hdr->checksum = 0;
        update_checksum(&checksum, (u_char*)hdr, sizeof(*hdr));
        
        if (read(fd, auth, sizeof(*auth)) != sizeof(*auth))
                return 1;
        update_checksum(&checksum, (u_char*)auth, sizeof(*auth));
        
        if (read(fd, acct, sizeof(*acct)) != sizeof(*acct))
                return 1;
        update_checksum(&checksum, (u_char*)acct, sizeof(*acct));

        here = lseek(fd, 0, SEEK_CUR);
        
        buf = emalloc(bufsize);
        while (1) {
                int rdsize = read(fd, buf, bufsize);
                if (rdsize <= 0)
                        break;
                update_checksum(&checksum, buf, rdsize);
        }

        lseek(fd, here, SEEK_SET);
        return checksum != saved_checksum;
}

int
statfile_read_nas_stat(fd, hdr)
        int fd;
        struct stat_header *hdr;
{
        struct nas_stat *np;
        unsigned n;

        server_stat.nas_count = 0;
        for (n = 0; n < hdr->nas_count; n++) {
                np = alloc_entry(sizeof(*np));
                if (read(fd, np, sizeof(*np)) != sizeof(*np))
                        return -1;
                np->next = NULL;
                if (!server_stat.nas_head)
                        server_stat.nas_head = np;
                else
                        server_stat.nas_tail->next = np;
                server_stat.nas_tail = np;
                server_stat.nas_count++;
        }
        return 0;
}

int
statfile_read_port_stat(fd, hdr)
        int fd;
        struct stat_header *hdr;
{
        struct port_stat *port;
        unsigned n;

        server_stat.port_count = 0;
        for (n = 0; n < hdr->port_count; n++) {
                port = alloc_entry(sizeof(*port));
                if (read(fd, port, sizeof(*port)) != sizeof(*port))
                        return -1;
                port->next = NULL;
                if (!server_stat.port_head)
                        server_stat.port_head = port;
                else
                        server_stat.port_tail->next = port;
                server_stat.port_tail = port;
                server_stat.port_count++;
        }
        return 0;
}

int
statfile_write(fd, data, length, sump)
        int fd;
        u_char *data;
        int length;
        unsigned *sump;
{
        if (write(fd, data, length) != length) {
                radlog(L_ERR|L_PERROR,
                       _("Error writing to statfile %s"),
                       radstat_path);
                return 1;
        }
        update_checksum(sump, data, length);
        return 0;
}

void
stat_init()
{
        struct stat_header hdr;
        struct timezone tz;
        int fd;

        memset(&hdr, 0, sizeof hdr);
        gettimeofday(&hdr.start_time, &tz);
        memset(&server_stat, 0, sizeof server_stat);
        fd = open(radstat_path, O_RDONLY);
        if (fd > 0) {
                if (statfile_verify(fd, &hdr,
                                    &server_stat.auth, &server_stat.acct)) {
                        close(fd);
                        fd = -1;
                        hdr.nas_count = 0;
                        hdr.port_count = 0;
                        gettimeofday(&hdr.start_time, &tz);
                } 
        }
        server_stat.nas_count = hdr.nas_count;
        server_stat.port_count = hdr.port_count;
        gettimeofday(&server_stat.start_time, &tz);
        server_stat.auth.reset_time = hdr.start_time;
        server_stat.acct.reset_time = hdr.start_time;
        server_stat.auth.status = serv_running;
        server_stat.acct.status = serv_running;
        radstat.start_time = hdr.start_time;

        if (fd > 0) {
                statfile_read_nas_stat(fd, &hdr);
                statfile_read_port_stat(fd, &hdr);
        
                close(fd);
        }
}

#define PERMS S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP

void
stat_done()
{
        struct stat_header hdr;
        unsigned checksum = 0;
        struct nas_stat *np;
        struct port_stat *pp;
        int fd;

        fd = open(radstat_path, O_RDWR|O_CREAT|O_TRUNC, PERMS);
        if (fd == -1) {
                radlog(L_ERR|L_PERROR,
                       _("Cannot open statfile %s"),
                       radstat_path);
                return;
        }
        memset(&hdr, 0, sizeof hdr);
        hdr.start_time = server_stat.start_time;
        
        lseek(fd, sizeof hdr, SEEK_SET);

        if (statfile_write(fd, (u_char*)&server_stat.auth,
                           sizeof(server_stat.auth), &checksum)
            || statfile_write(fd, (u_char*)&server_stat.acct,
                              sizeof(server_stat.acct), &checksum)) {
                close(fd);
                return;
        }

        for (np = server_stat.nas_head; np; np = np->next) {
                hdr.nas_count++;
                if (statfile_write(fd, (u_char*)np, sizeof(*np), &checksum)) {
                        close(fd);
                        return;
                }
        }
        
        for (pp = server_stat.port_head; pp; pp = pp->next) {
                hdr.port_count++;
                if (statfile_write(fd, (u_char*)pp, sizeof(*pp), &checksum)) {
                        close(fd);
                        return;
                }
        }
        
        lseek(fd, 0, SEEK_SET);
        update_checksum(&checksum, (u_char*)&hdr, sizeof(hdr));
        hdr.checksum = checksum;
        write(fd, &hdr, sizeof(hdr));
        close(fd);
}

PORT_STAT *
stat_alloc_port()
{
        PORT_STAT *port;
        
        port = alloc_entry(sizeof(*port));
        pthread_mutex_lock(&stat_mutex);
        if (!server_stat.port_head)
                server_stat.port_head = port;
        else
                server_stat.port_tail->next = port;
        server_stat.port_tail = port;
        pthread_mutex_unlock(&stat_mutex);
        return port;
}

PORT_STAT *
stat_find_port(nas, port_no)
        NAS *nas;
        int port_no;
{
        PORT_STAT *port;
        
        for (port = server_stat.port_head; port; port = port->next) {
                if (port->ip == nas->ipaddr && port->port_no == port_no)
                        return port;
        }

        /* Port not found */
        port = stat_alloc_port();
        port->ip = nas->ipaddr;
        port->port_no = port_no;
        
        return port;
}

int
stat_get_port_index(nas, port_no)
        NAS *nas;
        int port_no;
{
        PORT_STAT *port;
        int ind = 1;
        for (port = server_stat.port_head; port; port = port->next, ind++) {
                if (port->ip == nas->ipaddr && port->port_no == port_no)
                        return ind;
        }
        return 0;
}

int
stat_get_next_port_no(nas, port_no)
        NAS *nas;
        int port_no;
{
        PORT_STAT *port;
        int nextn = 0;
        
        for (port = server_stat.port_head; port; port = port->next) {
                if (port->ip == nas->ipaddr
                    && port->port_no > port_no
                    && (nextn == 0 || port->port_no < nextn))
                        nextn = port->port_no;
        }
        return nextn;
}

void
stat_update(ut, status)
        struct radutmp *ut;
        int status;
{
        NAS *nas;
        PORT_STAT *port;
        long dt;
        char ipbuf[DOTTED_QUAD_LEN];

        nas = nas_lookup_ip(ntohl(ut->nas_address));
        if (!nas) {
                radlog(L_WARN,
                    _("stat_update(): portno %d: can't find nas for IP %s"),
                    ut->nas_port,
                    ip_iptostr(ntohl(ut->nas_address), ipbuf));
                return;
        }
        if (nas->ipaddr == 0) /* DEFAULT nas */
                return;
        
        port = stat_find_port(nas, ut->nas_port);
        if (!port) {
                radlog(L_WARN,
                    _("stat_update(): port %d not found on NAS %s"),
                    ut->nas_port,
                    ip_iptostr(ntohl(ut->nas_address), ipbuf));
                return;
        }

        switch (status) {
        case DV_ACCT_STATUS_TYPE_START:
                if (port->start) {
                        dt = ut->time - port->start;
                        if (dt < 0) {
                                radlog(L_NOTICE,
                                    _("stat_update(START,%s,%s,%d): negative time skew"),
                                    ut->login, nas->shortname, ut->nas_port);
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
                                radlog(L_NOTICE,
                                    _("stat_update(STOP,%s,%s,%d): negative time skew"),
                                    ut->login, nas->shortname, ut->nas_port);
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

        debug(1,
                ("NAS %#x port %d: act %d, cnt %d, start %d, inuse %d/%d idle %d/%d",
                 port->ip, port->port_no, port->active,
                 port->count, port->start,
                 port->inuse, port->maxinuse.time,
                 port->idle, port->maxidle.time));
}

void
stat_count_ports()
{
        NAS *nas;
        struct nas_stat *statp;
        PORT_STAT *port;
        
        for (nas = nas_next(NULL); nas; nas = nas_next(nas)) {
                statp = nas->app_data;
                statp->ports_active = statp->ports_idle = 0;
        }
        
        radstat.port_active_count = radstat.port_idle_count = 0;

        for (port = server_stat.port_head; port; port = port->next) {
                nas = nas_lookup_ip(port->ip);
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
findportbyindex(ind)
        int ind;
{
        PORT_STAT *port;
        int i;

        if (ind < 1)
                return NULL;

        for (i = 1, port = server_stat.port_head;
             i < ind && port; port = port->next, i++)
                /* empty */ ;
        return port;
}

/* ************************************************************************* */

void
snmp_init_nas_stat()
{
        server_stat.nas_index = 1;
}

/* For a given ip_address return NAS statistics info associated with it.
   if no NAS with this address is known, return NULL */
struct nas_stat *
find_nas_stat(ip_addr)
        UINT4 ip_addr;
{
        struct nas_stat *np;

        for (np = server_stat.nas_head; np; np = np->next)
                if (np->ipaddr == ip_addr)
                        break;
        return np;
}


/* Attach NAS stat info to a given NAS structure. */
void
snmp_attach_nas_stat(nas)
        NAS *nas;
{
        struct nas_stat *np;

        np = find_nas_stat(nas->ipaddr);
        if (!np) {
                np = alloc_entry(sizeof(*np));
                if (!server_stat.nas_head)
                        server_stat.nas_head = np;
                else
                        server_stat.nas_tail->next = np;
                server_stat.nas_tail = np;
                np->ipaddr = nas->ipaddr;
                server_stat.nas_count++;
        }
        np->index = server_stat.nas_index++;
        nas->app_data = np;
}

static int
nas_ip_cmp(a, b)
        struct nas_stat **a, **b;
{
        return (*a)->ipaddr - (*b)->ipaddr;
}

void
snmp_sort_nas_stat()
{
        struct nas_stat **nsarray, *nsp;
        int i;

        nsarray = emalloc(server_stat.nas_count * sizeof(nsarray[0]));
        for (i = 0, nsp = server_stat.nas_head; 
                i < server_stat.nas_count; 
                i++, nsp = nsp->next) 
                nsarray[i] = nsp;       
        qsort(nsarray, server_stat.nas_count,
              sizeof(struct nas_stat*), nas_ip_cmp);
        for (i = 0, nsp = server_stat.nas_head; 
                i < server_stat.nas_count; 
                i++, nsp = nsp->next) 
                nsarray[i]->index = i + 1;
        efree(nsarray);
}

#endif
