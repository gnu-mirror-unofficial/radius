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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#include <sysdep.h>
#include <radiusd.h>

RADIUS_REQ *
radreq_alloc()
{
	return Alloc_entry(RADIUS_REQ);
}

/* Free a RADIUS_REQ struct.
 */
void 
radreq_free(radreq)
	RADIUS_REQ *radreq;
{
	free_string(radreq->realm);
	avl_free(radreq->server_reply);
	avl_free(radreq->request);
	free_request(radreq);
}


/* Turn printable string (dictionary type DATE) into correct tm struct entries
 */
static char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

int
user_gettime(valstr, tm)
	char *valstr; 
	struct tm *tm;
{
	int	i;

	/* Get the month */
	for (i = 0; i < 12; i++) {
		if (strncasecmp(months[i], valstr, 3) == 0) {
			tm->tm_mon = i;
			break;
		}
	}

	if (i == 12)
		return -1;
	
	valstr += 3;
	while (*valstr && isspace(*valstr))
		valstr++;

	if (!*valstr)
		return -1;
	
	/* Get the Day */
	tm->tm_mday = strtol(valstr, &valstr, 10);

	while (*valstr && isspace(*valstr))
		valstr++;
	if (!*valstr)
		return -1;
	
	/* Now the year */
	tm->tm_year = strtol(valstr, &valstr, 10) - 1900;

	return 0;
}

/* Lock `size' bytes on the file descriptor `fd' starting from `offset'.
 * `whence' determines from where the offset is counted (seek-like)
 */
void
rad_lock(fd, size, offset, whence)
        int fd;
	size_t size;
	off_t offset;
	int whence;
{
	struct flock fl;

	fl.l_type = F_RDLCK;
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	fcntl(fd, F_SETLKW, &fl);
}

/* Unlock `size' bytes on the file descriptor `fd' starting from `offset'.
 * `whence' determines from where the offset is counted (seek-like)
 */
void
rad_unlock(fd, size, offset, whence)
        int fd;
	size_t size;
	off_t offset;
	int whence;
{
	struct flock fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	fcntl(fd, F_SETLKW, &fl);
}

/* Find a struct keyword matching the given string. Return keyword token
 * number if found. Otherwise return default value `def'.
 */
int
xlat_keyword(kw, str, def)
	struct keyword *kw;
	char *str;
	int def;
{
        for ( ; kw->name; kw++) 
		if (strcmp(str, kw->name) == 0)
			return kw->tok;
	return def;
}

/* compose a full pathname from given path and filename
 */
char *
mkfilename(dir, name)
	char *dir;
	char *name;
{
	int len = strlen(dir) + strlen(name);
	char *p = emalloc(len+2);
	sprintf(p, "%s/%s", dir, name);
	return p;
}

/* compose a full pathname from given path, subdirectory and filename
 */
char *
mkfilename3(dir, subdir, name)
	char *dir;
	char *subdir;
	char *name;
{
	int len = strlen(dir) + strlen(subdir) + strlen(name);
	char *p = emalloc(len+3); /* two intermediate slashes and
				   * terminating zero
				   */
	sprintf(p, "%s/%s/%s", dir, subdir, name);
	return p;
}


#if 0
int
parse_exec_program(cmd, program, uid, gid)
	char *cmd;
	char **program;
	int  *uid;
	int  *gid;
{
	char *start;
	char *user_ptr = NULL;
	char *group_ptr = NULL;
	char *user, *group;
	int user_len;
	int group_len;
	struct passwd *pwd;
	struct group  *grp;
	
	if (*cmd == '(') {
		user_ptr = start = ++cmd;
		while (*cmd && *cmd != ')') {
			if (*cmd == ':') {
				user_len = cmd - start;
				break;
			}
			cmd++;
		}
		if (*cmd == ':') 
			group_ptr = start = ++cmd;
		while (*cmd && *cmd != ')')
			cmd++;
		if (*cmd == 0)
			return -1;
		group_len = cmd - start;
		if (!group_ptr)
			user_len = group_len;
		cmd++;
	}

	if (user_ptr && user_len) {
		user = emalloc(user_len+1);
		strncpy(user, user_ptr, user_len);
		user[user_len] = 0;
		pwd = getpwnam(user);
		if (!pwd) {
			radlog(L_ERR,
			       _("no such user in the system: `%s'"), user);
			efree(user);
			return -1;
		}
		efree(user);
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
	} else {
		pwd = getpwnam("root");
		*uid = *gid = 0;
	}

	if (group_ptr && group_len) {
		group = emalloc(group_len+1);
		strncpy(group, group_ptr, group_len);
		group[group_len] = 0;
		grp = getgrnam(group);
		if (!grp) {
			radlog(L_ERR,
			       _("no such group in the system: `%s'"), group);
			efree(group);
			return -1;
		}
		if (pwd) {
			int ok = 0;
			char **mp;
			
			for (mp = grp->gr_mem; mp; mp++)
				if (strcmp(*mp, pwd->pw_name) == 0) {
					ok++;
					break;
				}
			if (!ok) {
				radlog(L_ERR,
				       _("user %s not member of the group %s"),
				       pwd->pw_name, grp->gr_name);
				return -1;
			}
		}

		*gid = grp->gr_gid;
	}

	if (program)
		*program = cmd;

	return 0;
}
#endif				

int
backslash(c)
        int c;
{
	static char transtab[] = "b\bf\fn\nr\rt\t";
	char *p;

	for (p = transtab; *p; p += 2) {
		if (*p == c)
			return p[1];
	}
        return c;
}
	
