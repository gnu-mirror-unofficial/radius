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
#define RADIUS_MODULE 5
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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <radiusd.h>



#define MAXARGS 64


/*
 *	Execute a program on successful authentication.
 *	Return 0 if exec_wait == 0.
 *	Return the exit code of the called program if exec_wait != 0.
 *
 */
int
radius_exec_program(cmd, request, reply, exec_wait, user_msg)
	char *cmd;
	VALUE_PAIR *request;
	VALUE_PAIR **reply;
	int exec_wait;
	char **user_msg;
{
	int p[2];
	RETSIGTYPE (*oldsig)();
	pid_t pid;
	int argc;
	char *argv[MAXARGS];
	int n;
	char *ptr, *errp;
	int status;
	VALUE_PAIR *vp;
	FILE *fp;
	int line_num;
	char buffer[RAD_BUFFER_SIZE];
	struct passwd *pwd;
	struct group  *grp;
	int saved_uid, saved_gid;
	
	if (cmd[0] != '/') {
		radlog(L_ERR,
   _("radius_exec_program(): won't execute, not an absolute pathname: %s"),
		       cmd);
		return -1;
	}

	/* Check user/group
	 * FIXME: This should be checked *once* after re-reading the
	 *        configuration
	 */
	pwd = getpwnam(config.exec_user);
	if (!pwd) {
		radlog(L_ERR,
    _("radius_exec_program(): won't execute, no such user: %s"),
		       config.exec_user);
		return -1;
	}
	grp = getgrnam(config.exec_group);
	if (!grp) {
		radlog(L_ERR,
    _("radius_exec_program(): won't execute, no such group: %s"),
		       config.exec_group);
		return -1;
	} else if (pwd->pw_gid != grp->gr_gid) {
		int ok = 0;
		char **mp;

		for (mp = grp->gr_mem; *mp; mp++)
			if (strcmp(*mp, pwd->pw_name) == 0) {
				ok++;
				break;
			}
		if (!ok) {
			radlog(L_ERR,
     _("radius_exec_program(): won't execute, user %s not in group %s"),
			       pwd->pw_name, grp->gr_name);
			return -1;
		}
	}
	
	if (exec_wait) {
		if (pipe(p) != 0) {
			radlog(L_ERR|L_PERROR, _("couldn't open pipe"));
			p[0] = p[1] = 0;
			return -1;
		}
		if ((oldsig = signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
			radlog(L_ERR|L_PERROR, _("can't reset SIGCHLD"));
			return -1;
		}
	}

	if ((pid = fork()) == 0) {
		/* child branch */
		ptr = radius_xlate(buffer, sizeof(buffer), cmd, request, *reply);

		debug(1,
			("command line: %s", ptr));

		argc = 0;
		for (ptr = strtok(ptr, " \t"); ptr; ptr=strtok(NULL, " \t")) {
			if (argc > MAXARGS) {
				radlog(L_ERR,
				    _("radius_exec_program(): too many arguments"));
				return -1;
			}
			argv[argc++] = ptr;
		}
		argv[argc++] = NULL;

		if (exec_wait) {
			if (close(p[0]))
				radlog(L_ERR|L_PERROR, _("can't close pipe"));
			if (dup2(p[1], 1) != 1)
				radlog(L_ERR|L_PERROR, _("can't dup stdout"));
		}

		for(n = 32; n >= 3; n--)
			close(n);

		chdir("/tmp");
		
		saved_uid = geteuid();
		saved_gid = getegid();
		
		radlog(L_NOTICE,
		       "radius_exec_program(): setting %d:%d",
		       pwd->pw_uid,grp->gr_gid);
		if (setegid(grp->gr_gid)) {
			radlog(L_CRIT|L_PERROR,
			       _("radius_exec_program(): setegid failed"));
		}
		if (seteuid(pwd->pw_uid)) {
			radlog(L_CRIT|L_PERROR,
			       _("radius_exec_program(): seteuid failed"));
		}

		execvp(argv[0], argv);

		seteuid(saved_uid);
		setegid(saved_gid);

		radlog(L_CRIT|L_PERROR,
		       _("radius_exec_program(): cannot run %s"),
		       argv[0]);
		exit(1);
	}

	/* Parent branch */ 
	if (pid < 0) {
		radlog(L_ERR|L_PERROR, _("can't fork"));
		return -1;
	}
	if (!exec_wait)
		return 0;

	if (close(p[1]))
		radlog(L_ERR|L_PERROR, _("can't close pipe"));

	fp = fdopen(p[0], "r");

	vp = NULL;
	line_num = 0;
	while (ptr = fgets(buffer, sizeof(buffer), fp)) {
		line_num++;
		debug(1,
			("got `%s'", buffer));
		if (userparse(ptr, &vp, &errp)) {
			radlog(L_ERR,
			    _("<stdout of %s>:%d: %s"),
			    cmd, line_num, errp);
			pairfree(vp);
			vp = NULL;
		}
	}

	fclose(fp);
	/*close(p[0]);*/

	if (vp) {
		pairmove(reply, &vp);
	}

	
	while (waitpid(pid, &status, 0) != pid)
		;

	if (signal(SIGCHLD, oldsig) == SIG_ERR)
		radlog(L_CRIT|L_PERROR,
			_("can't restore SIGCHLD"));
	sig_cleanup(SIGCHLD);

	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		debug(1,
			("returned: %d", status));
		return status;
	}
	radlog(L_ERR, _("radius_exec_program(): abnormal child exit"));

	return 1;
}
