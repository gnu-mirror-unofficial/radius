/* This file is part of GNU RADIUS.
   Copyright (C) 2001, Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <fcntl.h>

#include <radius.h>
#include <radutmp.h>

struct _radut_file {
	int fd;
	int eof;
	int readonly;
	struct radutmp ut;
};

radut_file_t
rut_setent(name, append)
	char *name;
	int append;
{
	int fd;
	int ro = 0;
	radut_file_t fp;
	
	if ((fd = open(name, O_RDWR|O_CREAT, 0644)) < 0) {
		ro = 1;
		fd = open(name, O_RDONLY);
	}
	if (!fd) {
		radlog(L_ERR|L_PERROR, 
		       _("rut_setent(): cannot open"));
		return NULL;
	}
	if (append)
		lseek(fd, 0, SEEK_END);
	fp = emalloc(sizeof(*fp));
	fp->fd = fd;
	fp->eof = append;
	fp->readonly = ro;
	return fp;
}

void
rut_rewind(file)
	radut_file_t file;
{
	lseek(file->fd, 0, SEEK_SET);
	file->eof = 0;
}

void
rut_endent(file)
	radut_file_t file;
{
	if (!file)
		return;
	close(file->fd);
	efree(file);
}

struct radutmp *
rut_getent(file)
	radut_file_t file;
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
rut_putent(file, ent)
	radut_file_t file;
	struct radutmp *ent;
{
	if (file->readonly) {
		radlog(L_ERR, "rut_putent(): file opened readonly");
		return -1;
	}
	/* Step back one record unless we have reached eof */
	if (!file->eof &&
	    lseek(file->fd, -(off_t)sizeof(file->ut), SEEK_CUR) < 0) {
		radlog(L_ERR|L_PERROR, 
		       _("rut_putent(): negative lseek"));
		lseek(file->fd, (off_t)0, SEEK_SET);
		return -1;
	}
	/* Lock the utmp file.  */
	rad_lock(file->fd, sizeof(*ent), 0, SEEK_CUR);

	if (write(file->fd, ent, sizeof(*ent)) != sizeof(*ent)) {
		radlog(L_ERR|L_PERROR, 
		       _("rut_putent(): write"));
	}

	memcpy(&file->ut, ent, sizeof(file->ut));
	       
	/* Unlock the file */
	rad_unlock(file->fd, sizeof(*ent), -(off_t)sizeof(file->fd), SEEK_CUR);

	return 0;
}
	
int
radutmp_putent(filename, ut, status)
	char *filename;
	struct radutmp *ut;
	int status;
{
	radut_file_t file;
	struct radutmp *ent;
	int rc = PUTENT_SUCCESS;

	if ((file = rut_setent(filename, 0)) == NULL)
		return PUTENT_NOENT;

        /* find matching entry */
	while ((ent = rut_getent(file)) != NULL &&
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
				radlog(L_INFO,
		_("login: entry for NAS %s port %d duplicate"),
				       format_ipaddr(ntohl(ent->nas_address)),
				       ent->nas_port);
			} else {
				radlog(L_INFO,
	        _("login: entry for NAS %s port %d wrong order"),
				       format_ipaddr(ntohl(ent->nas_address)),
				       ent->nas_port);
			}
		}

	} else { /* session IDs differ */
			
		if (status == DV_ACCT_STATUS_TYPE_STOP) {
			if (ent->type == P_LOGIN) {
				radlog(L_ERR,
   _("logout: entry for NAS %s port %d has wrong ID (expected %s found %s)"),
				       format_ipaddr(ntohl(ut->nas_address)),
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
			radlog(L_ERR,
			 _("logout: login entry for NAS %s port %d not found"),
			       format_ipaddr(ntohl(ut->nas_address)), ut->nas_port);
		}
		break;
	}
	rut_putent(file, ut);
	rut_endent(file);
	return rc;
}
	
int
radwtmp_putent(filename, ut)
	char *filename;
	struct radutmp *ut;
{
	radut_file_t file;
		
	file = rut_setent(filename, 1);
	if (file == NULL) {
		radlog(L_ERR|L_PERROR, _("can't open %s"), radwtmp_path);
		return 1;
	}
	rut_putent(file, ut);
	rut_endent(file);
	return 0;
}

