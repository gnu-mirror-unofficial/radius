/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <radlib.h>

struct _radut_file {
	const char *name;
        int fd;
        int eof;
        int readonly;
	int append;
        struct radutmp ut;
};

radut_file_t
grad_ut_setent(const char *name, int append)
{
        int fd;
        int ro = 0;
        radut_file_t fp;
        
        if ((fd = open(name, O_RDWR|O_CREAT, 0644)) < 0) {
                ro = 1;
                fd = open(name, O_RDONLY);
        }
        if (fd == -1) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("grad_ut_setent(): cannot open `%s'"), name);
                return NULL;
        }
        fp = grad_emalloc(sizeof(*fp));
	fp->name = name;
        fp->fd = fd;
        fp->append = append;
        fp->eof = append;
        fp->readonly = ro;
        return fp;
}

void
grad_ut_rewind(radut_file_t file)
{
        lseek(file->fd, 0, SEEK_SET);
        file->eof = 0;
}

void
grad_ut_endent(radut_file_t file)
{
        if (!file)
                return;
        close(file->fd);
        grad_free(file);
}

struct radutmp *
grad_ut_getent(radut_file_t file)
{
        int rc;
        
        rc = read(file->fd, &file->ut, sizeof(file->ut));
        if (rc == 0) {
                file->eof++;
                return NULL;
        } else if (rc != sizeof(file->ut)) 
                return NULL;
        return &file->ut;
}

int
grad_ut_putent(radut_file_t file, struct radutmp *ent)
{
        if (file->readonly) {
                grad_log(GRAD_LOG_ERR,
			 "grad_ut_putent(%s): file opened readonly",
			 file->name);
                return -1;
        }

	if (file->append) {
		off_t size;
		grad_lock_file(file->fd, sizeof(*ent), 0, SEEK_END);
		size = lseek(file->fd, 0, SEEK_END);
		if (size < 0) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
				 "grad_ut_putent(%s): lseek",
				 file->name);
			grad_unlock_file(file->fd, sizeof(*ent), 0, SEEK_END);
			return -1;
		}
		if (size % sizeof (*ent)) {
			grad_log(GRAD_LOG_CRIT,
				 "grad_ut_putent(%s): File size is not a multiple of radutmp entry size",
				 file->name);
			grad_unlock_file(file->fd, sizeof(*ent), 0, SEEK_END);
			return -1;
		}
	} else {
		/* Step back one record unless we have reached eof */
		if (!file->eof &&
		    lseek(file->fd, -(off_t)sizeof(file->ut), SEEK_CUR) < 0) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
				 "grad_ut_putent(%s): lseek",
				 file->name);
			lseek(file->fd, (off_t)0, SEEK_SET);
			return -1;
		}
		/* Lock the utmp file.  */
		grad_lock_file(file->fd, sizeof(*ent), 0, SEEK_CUR);
	}
	
        if (write(file->fd, ent, sizeof(*ent)) != sizeof(*ent)) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         "grad_ut_putent(%s): write",
			 file->name);
		grad_lock_file(file->fd, sizeof(*ent), 0, SEEK_CUR);
		return -1;
        }

        memcpy(&file->ut, ent, sizeof(file->ut));
               
        /* Unlock the file */
        grad_unlock_file(file->fd, sizeof(*ent),
			 -(off_t)sizeof(file->fd), SEEK_CUR);

        return 0;
}
        
int
grad_utmp_putent(const char *filename, struct radutmp *ut, int status)
{
        radut_file_t file;
        struct radutmp *ent;
        char ipbuf[GRAD_IPV4_STRING_LENGTH];
        int rc = PUTENT_SUCCESS;

        if ((file = grad_ut_setent(filename, 0)) == NULL)
                return PUTENT_NOENT;

        /* find matching entry */
        while ((ent = grad_ut_getent(file)) != NULL &&
               (ent->nas_address != ut->nas_address ||
                ent->nas_port    != ut->nas_port))
                /* nothing */;

        if (!ent) {
                rc = PUTENT_NOENT;
        } else if (strncmp(ent->session_id, ut->session_id,
                           sizeof(ent->session_id)) == 0) {
                /* Exact match. */

                switch (status) {
                case DV_ACCT_STATUS_TYPE_ALIVE:
                        if (ent->type == P_LOGIN) {
                                ut->time = ent->time;
                                if (ent->login[0] != 0)
                                        rc = PUTENT_UPDATE;
                        }
                        break;
                        
                case DV_ACCT_STATUS_TYPE_START:
                        if (ent->time < ut->time)
                                break;
                        if (ent->type == P_LOGIN) {
                                grad_log(GRAD_LOG_INFO,
                _("login: entry for NAS %s port %d duplicate"),
                                       grad_ip_iptostr(ntohl(ent->nas_address),
						       ipbuf),
                                       ent->nas_port);
                        } else {
                                grad_log(GRAD_LOG_INFO,
                _("login: entry for NAS %s port %d wrong order"),
                                       grad_ip_iptostr(ntohl(ent->nas_address),
						       ipbuf),
                                       ent->nas_port);
                        }
                }

        } else { /* session IDs differ */
                        
                if (status == DV_ACCT_STATUS_TYPE_STOP) {
                        if (ent->type == P_LOGIN) {
                                grad_log(GRAD_LOG_ERR,
   _("logout: entry for NAS %s port %d has wrong ID (expected %s found %s)"),
                                         grad_ip_iptostr(ntohl(ut->nas_address),
					 	         ipbuf),
                                         ent->nas_port,
                                         ut->session_id,
                                         ent->session_id);
                        }
                }
                
        }

        if (ent) 
                ut->duration = ut->time - ent->time;
        
        switch (status) {
        case DV_ACCT_STATUS_TYPE_START:
        case DV_ACCT_STATUS_TYPE_ALIVE:
                ut->type = P_LOGIN;
                break;

        case DV_ACCT_STATUS_TYPE_STOP:
                ut->type = P_IDLE;
                if (!ent) {
                        grad_log(GRAD_LOG_ERR,
                         _("logout: login entry for NAS %s port %d not found"),
                               grad_ip_iptostr(ntohl(ut->nas_address), ipbuf), 
                               ut->nas_port);
                }
                break;
        }
        grad_ut_putent(file, ut);
        grad_ut_endent(file);
        return rc;
}
        
int
grad_radwtmp_putent(const char *filename, struct radutmp *ut)
{
        radut_file_t file;
                
        file = grad_ut_setent(filename, 1);
        if (file == NULL) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open %s"), grad_wtmp_file);
                return 1;
        }
        grad_ut_putent(file, ut);
        grad_ut_endent(file);
        return 0;
}

