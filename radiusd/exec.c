/* This file is part of GNU Radius.
   Copyright (C) 2002,2003,2004,2005,2006,2007,
   2008 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

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
#include <syslog.h>

#include <radiusd.h>
#include <radius/argcv.h>
#include <radius/symtab.h>
#include <rewrite.h>

int
radius_get_user_ids(RADIUS_USER *usr, const char *name)
{
	struct passwd *pwd = getpwnam(name);

	if (!pwd) {
		grad_log(GRAD_LOG_ERR, _("no such user: %s"), name);
		return 1;
	}
	grad_string_replace(&usr->username, name);
	usr->uid = pwd->pw_uid;
	usr->gid = pwd->pw_gid;
	return 0;
}

int
radius_switch_to_user(RADIUS_USER *usr)
{
	int rc = 0;
	gid_t emptygidset[1];

	if (usr->username == NULL)
		return 0;
	
	/* Reset group permissions */
	emptygidset[0] = usr->gid ? usr->gid : getegid();
	if (geteuid() == 0 && setgroups(1, emptygidset)) {
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("setgroups(1, %lu) failed"),
		         (u_long) emptygidset[0]);
		rc = 1;
	}

	/* Switch to the user's gid. On some OSes the effective gid must
	   be reset first */

#if defined(HAVE_SETEGID)
	if ((rc = setegid(usr->gid)) < 0)
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("setegid(%lu) failed"), (u_long) usr->gid);
#elif defined(HAVE_SETREGID)
	if ((rc = setregid(usr->gid, usr->gid)) < 0)
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("setregid(%lu,%lu) failed"),
		         (u_long) usr->gid, (u_long) usr->gid);
#elif defined(HAVE_SETRESGID)
	if ((rc = setresgid(usr->gid, usr->gid, usr->gid)) < 0)
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("setresgid(%lu,%lu,%lu) failed"),
		         (u_long) usr->gid,
		         (u_long) usr->gid,
		         (u_long) usr->gid);
#endif

	if (rc == 0 && usr->gid != 0) {
		if ((rc = setgid(usr->gid)) < 0 && getegid() != usr->gid) 
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
			         _("setgid(%lu) failed"), (u_long) usr->gid);
		if (rc == 0 && getegid() != usr->gid) {
			grad_log(GRAD_LOG_ERR,
			         _("cannot set effective gid to %lu"),
			         (u_long) usr->gid);
			rc = 1;
		}
	}

	/* Now reset uid */
	if (rc == 0 && usr->uid != 0) {
		uid_t euid;

		if (setuid(usr->uid)
		    || geteuid() != usr->uid
		    || (getuid() != usr->uid
			&& (geteuid() == 0 || getuid() == 0))) {
			
#if defined(HAVE_SETREUID)
			if (geteuid() != usr->uid) {
				if (setreuid(usr->uid, -1) < 0) { 
					grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
					         _("setreuid(%lu,-1) failed"),
					         (u_long) usr->uid);
					rc = 1;
				}
				if (setuid(usr->uid) < 0) {
					grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
					         _("second setuid(%lu) failed"),
					         (u_long) usr->uid);
					rc = 1;
				}
			} else
#endif
				{
					grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
					         _("setuid(%lu) failed"),
					         (u_long) usr->uid);
					rc = 1;
				}
		}
	

		euid = geteuid();
		if (usr->uid != 0 && setuid(0) == 0) {
			grad_log(GRAD_LOG_ERR, 
                                 _("seteuid(0) succeeded when it should not"));
			rc = 1;
		} else if (usr->uid != euid && setuid(euid) == 0) {
			grad_log(GRAD_LOG_ERR, 
                                 _("cannot drop non-root setuid privileges"));
			rc = 1;
		}

	}

	return rc;
}

int
radius_exec_command(char *cmd)
{
        int n;
        grad_avp_t *vp;
	pid_t pid;
	int status;
	RETSIGTYPE (*oldsig)();
	
        if (cmd[0] != '/') {
                grad_log(GRAD_LOG_ERR,
   _("radius_exec_command(): won't execute, not an absolute pathname: %s"),
                         cmd);
                return -1;
        }

	if ((oldsig = grad_set_signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("can't reset SIGCHLD"));
		return -1;
        } 

        if ((pid = fork()) == 0) {
                int argc;
                char **argv;

                grad_argcv_get(cmd, "", NULL, &argc, &argv);

		/* Leave open only stderr */
                for (n = grad_max_fd(); n > 2; n--)
                        close(n);
		close(0);
		close(1);
		
                chdir("/tmp");

                if (radius_switch_to_user(&exec_user))
			exit(2);
		
                execvp(argv[0], argv);

                /* Report error via syslog: we might not be able
		   to restore initial privileges if we were started
		   as non-root. */
                openlog("radiusd", LOG_PID, LOG_USER);
                syslog(LOG_ERR, "can't run %s (ruid=%lu, euid=%lu): %m",
                       argv[0], (u_long) getuid(), (u_long) geteuid());
                exit(2);
        }

        /* Parent branch */ 
        if (pid < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "fork");
                return -1;
        }

	waitpid(pid, &status, 0);
	if (grad_set_signal(SIGCHLD, oldsig) == SIG_ERR)
		grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR,
			 _("can't restore SIGCHLD"));

        if (WIFEXITED(status)) {
                status = WEXITSTATUS(status);
                GRAD_DEBUG1(1, "returned: %d", status);
                if (status == 2) {
                        grad_log(GRAD_LOG_ERR,
                                 _("can't run external program `%s' "
                                   "(reason reported via syslog channel "
                                   "user.err)"),
			         cmd);
                }
        } else {
		char buffer[RAD_BUFFER_SIZE];
		
		format_exit_status(buffer, sizeof buffer, status);
		
		grad_log(GRAD_LOG_ERR,
		         _("external program `%s' %s"), cmd, buffer);
	}
	
        return status;
}

/* Execute a program on successful authentication.
   Return the exit code of the called program if exec_wait is true,
   return 0 otherwise.  */
int
radius_exec_program(char *cmd, radiusd_request_t *req, grad_avp_t **reply,
		    int exec_wait)
{
        int p[2];
        int n;
        char *ptr, *errp;
        grad_avp_t *vp;
        FILE *fp;
        int line_num;
        char buffer[RAD_BUFFER_SIZE];
	pid_t pid;
	int status;
	RETSIGTYPE (*oldsig)();
	
        if (cmd[0] != '/') {
                grad_log(GRAD_LOG_ERR,
   _("radius_exec_program(): won't execute, not an absolute pathname: %s"),
                         cmd);
                return -1;
        }

        if (exec_wait) {
                if (pipe(p) != 0) {
                        grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("couldn't open pipe"));
                        return -1;
                }
		if ((oldsig = grad_set_signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("can't reset SIGCHLD"));
			return -1;
		}
        } 

        if ((pid = fork()) == 0) {
                int argc;
                char **argv;

                GRAD_DEBUG1(1, "command line: %s", cmd);

                grad_argcv_get(cmd, "", NULL, &argc, &argv);
                
                if (exec_wait) {
                        if (close(p[0]))
                                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
					 _("can't close pipe"));
                        if (p[1] != 1 && dup2(p[1], 1) != 1)
                                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
					 _("can't dup stdout"));
                } else
			close(1);

                for (n = grad_max_fd(); n >= 3; n--)
                        close(n);

                chdir("/tmp");

                if (radius_switch_to_user(&exec_user))
			exit(2);
		
                execvp(argv[0], argv);

                /* Report error via syslog: we might not be able
		   to restore initial privileges if we were started
		   as non-root. */
                openlog("radiusd", LOG_PID, LOG_USER);
                syslog(LOG_ERR, "can't run %s (ruid=%lu, euid=%lu): %m",
                       argv[0], (u_long) getuid(), (u_long) geteuid());
                exit(2);
        }

        /* Parent branch */ 
        if (pid < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "fork");
                return -1;
        }
        if (!exec_wait)
                return 0;

        if (close(p[1]))
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, _("can't close pipe"));

        fp = fdopen(p[0], "r");

        vp = NULL;
        line_num = 0;

        while (ptr = fgets(buffer, sizeof(buffer), fp)) {
                line_num++;
                GRAD_DEBUG1(1, "got `%s'", buffer);
                if (userparse(ptr, &vp, &errp)) {
                        grad_log(GRAD_LOG_ERR,
			         _("<stdout of %s>:%d: %s"),
			         cmd, line_num, errp);
                        grad_avl_free(vp);
                        vp = NULL;
                }
        }

        fclose(fp);

	waitpid(pid, &status, 0);
	if (grad_set_signal(SIGCHLD, oldsig) == SIG_ERR)
		grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR,
			 _("can't restore SIGCHLD"));

        if (WIFEXITED(status)) {
                status = WEXITSTATUS(status);
                GRAD_DEBUG1(1, "returned: %d", status);
                if (status == 2) {
                        grad_log(GRAD_LOG_ERR,
                                 _("can't run external program `%s' "
                                   "(reason reported via syslog channel "
                                   "user.err)"),
			         cmd);
                }
        } else {
		format_exit_status(buffer, sizeof buffer, status);
		
		grad_log(GRAD_LOG_ERR,
		         _("external program `%s' %s"), cmd, buffer);
	}

        if (vp && reply) 
                grad_avl_merge(reply, &vp);
	grad_avl_free(vp);

        return status;
}

pid_t
radius_run_filter(int argc, char **argv, char *errfile, int *p)
{
	pid_t  pid;
	int    rightp[2], leftp[2];
	int i;

	pipe(leftp);
	pipe(rightp);
    
	switch (pid = fork()) {

		/* The child branch.  */
	case 0:
		/* attach the pipes */

		/* Left-end. It is important that it be processed first,
		   since it may contain descriptors 0 and 1 */
		if (leftp[0] != 0) {
			close(0);
			dup2(leftp[0], 0);
		}
		close(leftp[1]);
		
		/* Right-end */
		if (rightp[1] != 1) {
			close(1);
			dup2(rightp[1], 1);
		}
		close(rightp[0]); 

		/* Error output */
		i = open(errfile, O_CREAT|O_WRONLY|O_APPEND, 0644);
                if (i > 0 && i != 2) {
                        dup2(i, 2);
			close(i);
		}
		
		/* Close unneded descripitors */
		for (i = grad_max_fd(); i > 2; i--)
			close(i);

		if (radius_switch_to_user(&exec_user))
			exit(2);
		execvp(argv[0], argv);
		
                /* Report error via syslog: we might not be able
		   to restore initial privileges if we were started
		   as non-root. */
                openlog("radiusd", LOG_PID, LOG_USER);
                syslog(LOG_ERR, "can't run %s (ruid=%d, euid=%d): %m",
                       argv[0], getuid(), geteuid());
                exit(2);
		/********************/

		/* Parent branches: */
	case -1:
		/* Fork has failed */
		/* Restore things */
		close(rightp[0]);
		close(rightp[1]);
		close(leftp[0]);
		close(leftp[1]);
		break;
		
	default:
		p[0]  = rightp[0];
		close(rightp[1]);
		
		p[1] = leftp[1];
		close(leftp[0]);
	}
	return pid;
}

typedef struct filter_symbol Filter;

/* NOTE,NOTE,NOTE: The code below works on the assumption that
   R_AUTH=0, R_ACCT=1 */

#define FILTER_MAX  2

struct filter_symbol {
        struct filter_symbol *next;
	char *name;                 /* Name of the filter */
	/* Configuration data */
	int line_num;               /* Number of line in raddb/config where
				       the filter is defined */
	int  argc;                  /* Number of entries in the argv */
        char **argv;                /* Invocation vector */
	char *errfile;              /* Filename for error output (fd 2) */
	struct {
		char *input_fmt;    
		int wait_reply;
		int on_fail;
	} descr[FILTER_MAX];
	
	/* Runtime data */
	pid_t  pid;                 /* Pid of the filter process */
	size_t lines_input;         /* Number of lines read from the filter */
	size_t lines_output;        /* Number of lines written to the filter */
	int    input;               /* Input file descriptor */
	int    output;              /* Output file descriptor */
}; 

static grad_symtab_t *filter_tab;

struct cleanup_info {
	pid_t pid;
	int status;
};
	
static int
filter_cleanup_proc(void *ptr, grad_symbol_t *sym)
{
	struct cleanup_info *info = ptr;
	Filter *filter = (Filter *) sym;

	if (filter->pid == info->pid) {
		static char buffer[512];
		
		format_exit_status(buffer, sizeof buffer, info->status);
		grad_log(GRAD_LOG_ERR,
		         _("filter %s (pid %d) %s (in: %u, out: %u)"),
		         filter->name, filter->pid,
		         buffer,
		         filter->lines_input, filter->lines_output);
		filter->pid = 0;
		return 1;
	}
	return 0;
}

/* Note: signal-safe */
void
filter_cleanup(pid_t pid, int status)
{	
	struct cleanup_info info;
	info.pid = pid;
	info.status = status;
	grad_symtab_iterate(filter_tab, filter_cleanup_proc, &info);
}

void
filter_close(Filter *filter)
{
	if (filter->pid == -1) 
		return;

	if (filter->input >= 0) {
		close(filter->input);
		filter->input = -1;
	}
	if (filter->output >= 0) {
		close(filter->output);
		filter->output = -1;
	}
	if (filter->pid > 0) {
		kill(filter->pid, SIGTERM);
		filter->pid = 0;
	}
}

void
filter_kill(Filter *filter)
{
	if (filter->pid == 0)  
		return;
	kill(filter->pid, SIGKILL);
}

static Filter *
filter_open(char *name, radiusd_request_t *req, int type, int *errp)
{
	Filter *filter = grad_sym_lookup(filter_tab, name);
	if (!filter) {
		grad_log_req(GRAD_LOG_ERR, req->request,
			     _("filter %s is not declared"),
			     name);
		*errp = -1;
		return NULL;
	}

	*errp = filter->descr[type].on_fail;
	if (filter && filter->pid <= 0) {
		int pipe[2];

		filter->pid = radius_run_filter(filter->argc,
						filter->argv,
						filter->errfile,
						pipe);
		
		if (filter->pid <= 0) {
			grad_log_req(GRAD_LOG_ERR|GRAD_LOG_PERROR, req->request,
				     _("cannot run filter %s"),
				     name);
			filter = NULL;
		} else { 
			if (!filter->descr[R_AUTH].wait_reply
			    && !filter->descr[R_ACCT].wait_reply) {
				close(pipe[0]);
				filter->input = -1;
			} else
				filter->input  = pipe[0];
			filter->output = pipe[1];
			filter->lines_input = 0;
			filter->lines_output = 0;
		}
	}

	if (filter && kill(filter->pid, 0)) {
		grad_log_req(GRAD_LOG_ERR|GRAD_LOG_PERROR, req->request,
			     _("filter %s"), name);
		filter_close(filter);
		filter = NULL;
	}

	return filter;
}

char *
filter_xlate(struct obstack *sp, char *fmt, radiusd_request_t *radreq)
{
	return util_xlate(sp, fmt, radreq->request);
}

static int
filter_write(Filter *filter, char *fmt, radiusd_request_t *radreq)
{
	int rc, length;
	struct obstack stack;
	char *str;
	
	if (!fmt)
		return -1;
	
	obstack_init(&stack);
	str = filter_xlate(&stack, fmt, radreq);
	if (!str) {
		rc = length = 0;
	} else {
		char nl = '\n';
		length = strlen(str);
		GRAD_DEBUG2(1, "%s < \"%s\"", filter->name, str);
		rc = write(filter->output, str, length);
		if (rc == length) {
			if (write(filter->output, &nl, 1) == 1)
				rc++;
		}

	}
	obstack_free(&stack, NULL);
	filter->lines_output++;
	return rc != length + 1;
}

static int
filter_read(Filter *filter, int type, char *buffer, size_t buflen)
{
	int rc;
	int rbytes = 0;
	
	while (1) {
		rc = -1;
		if (rbytes >= buflen-1) {
			errno = ENOMEM;
			break;
		}
		if (read(filter->input, buffer + rbytes, 1) != 1) {
			if (errno == EINTR)
				continue;
			break;
		}
		rbytes++;
		if (buffer[rbytes-1] == '\n') {
			rc = 0;
			break;
		}
	} 

	if (rc == 0) {
		buffer[rbytes] = 0;
		filter->lines_input++;
		return rbytes;
	}
	return rc;
}

/* Interface triggered by Auth-External-Filter.
   Returns: 0   -- Authentication succeeded
            !0  -- Authentication failed */
int
filter_auth(char *name, radiusd_request_t *req, grad_avp_t **reply_pairs)
{
	Filter *filter;
	int rc = -1;
	int err;
	
	filter = filter_open(name, req, R_AUTH, &err);
	if (!filter)
		return err;
	if (filter->pid == -1)
		rc = err;
	else if (filter_write(filter, filter->descr[R_AUTH].input_fmt, req)) 
		rc = err;
	else if (!filter->descr[R_AUTH].wait_reply) 
		rc = 0;
	else {
		int status;
		char buffer[1024];

		status = filter_read(filter, R_AUTH, buffer, sizeof buffer);
			
		if (status <= 0) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		       	         _("reading from filter %s"),
		       	         filter->name);
			filter_close(filter);
			rc = err;
		} else if (isdigit(buffer[0])) {
			char *ptr;
			grad_avp_t *vp = NULL;
			char *errp;

			GRAD_DEBUG2(1, "%s > \"%s\"", filter->name, buffer);
			rc = strtoul(buffer, &ptr, 0);
			if (userparse(ptr, &vp, &errp)) {
				grad_log(GRAD_LOG_ERR,
				         _("<stdout of %s>:%d: %s"),
				         filter->name,
				         filter->lines_output,
				         errp);
				grad_avl_free(vp);
			} else 
				grad_avl_merge(reply_pairs, &vp);
		} else {
			grad_log(GRAD_LOG_ERR,
			         _("filter %s (auth): bad output: %s"),
			         filter->name, buffer);
			rc = err;
		}
	}

	return rc;
}

int
filter_acct(char *name, radiusd_request_t *req)
{
	Filter *filter;
	int rc = -1;
	int err;
	
	filter = filter_open(name, req, R_ACCT, &err);
	if (!filter)
		return err;
	if (filter->pid == -1)
		rc = err;
	else if (filter_write(filter, filter->descr[R_ACCT].input_fmt, req)) 
		rc = err;
	else if (!filter->descr[R_ACCT].wait_reply) 
		rc = 0;
	else {
		int status;
		char buffer[1024];

		status = filter_read(filter, R_ACCT, buffer, sizeof buffer);

		if (status <= 0) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		       	         _("reading from filter %s"),
		       	         filter->name);
			rc = err;
			filter_close(filter);
		} else if (isdigit(buffer[0])) {
			char *ptr;

			GRAD_DEBUG2(1, "%s > \"%s\"", filter->name, buffer);
			rc = strtoul(buffer, &ptr, 0);
			if (!isspace(*ptr)) {
				grad_log(GRAD_LOG_ERR,
				         _("filter %s (acct): bad output: %s"),
				         filter->name, buffer);
				return -1;
			}
		} else {
			grad_log(GRAD_LOG_ERR,
			         _("filter %s (acct): bad output: %s"),
			         filter->name, buffer);
			rc = err;
		}
	}

	return rc;
}


/* ***************************** Configuration ***************************** */

static struct filter_symbol filter_symbol;

static int
free_symbol_entry(Filter *filter)
{
	grad_free(filter->descr[R_AUTH].input_fmt);
	grad_free(filter->descr[R_ACCT].input_fmt);
	grad_argcv_free(filter->argc, filter->argv);
	grad_free(filter->errfile);
	if (filter->pid > 0)
		filter_close(filter);
	return 0;
}

int
filters_stmt_term(int finish, void *block_data, void *handler_data)
{
	if (!finish) {
		if (filter_tab)
			grad_symtab_clear(filter_tab);
		else
			filter_tab = grad_symtab_create(sizeof(Filter),
						        free_symbol_entry);
	}
	return 0;
}

static int
filter_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
		    void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	memset(&filter_symbol, 0, sizeof filter_symbol);
	filter_symbol.line_num = cfg_line_num;
	filter_symbol.name = argv[1].v.string;
	filter_symbol.errfile = NULL;
	filter_symbol.descr[R_AUTH].wait_reply = 1;
	filter_symbol.descr[R_ACCT].wait_reply = 1;
	return 0;
}

static int
filter_stmt_end(void *block_data, void *handler_data)
{
	if (filter_symbol.argc) {
		Filter *sym = grad_sym_lookup_or_install(filter_tab,
						         filter_symbol.name,
						         1);
		if (sym->argc) {
			grad_log(GRAD_LOG_ERR,
			         _("%s:%d: filter already declared at %s:%d"),
			         cfg_filename, cfg_line_num,
			         cfg_filename, sym->line_num);
			return 0;
		}

		sym->line_num = filter_symbol.line_num;
		sym->argc     = filter_symbol.argc;
		sym->argv     = filter_symbol.argv;
		sym->descr[R_AUTH].input_fmt =
			grad_estrdup(filter_symbol.descr[R_AUTH].input_fmt);
		sym->descr[R_ACCT].input_fmt =
			grad_estrdup(filter_symbol.descr[R_ACCT].input_fmt);
		sym->descr[R_AUTH].wait_reply =
			filter_symbol.descr[R_AUTH].wait_reply;
		sym->descr[R_ACCT].wait_reply =
			filter_symbol.descr[R_ACCT].wait_reply;
		sym->descr[R_AUTH].on_fail =
			!filter_symbol.descr[R_AUTH].on_fail;
		sym->descr[R_ACCT].on_fail =
			!filter_symbol.descr[R_ACCT].on_fail;
		sym->errfile  = grad_estrdup(filter_symbol.errfile);
		sym->pid = 0;
	}
	return 0;
}

static int
exec_path_handler(int argc, cfg_value_t *argv,
		  void *block_data, void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	
	if (grad_argcv_get(argv[1].v.string, "", NULL,
		      &filter_symbol.argc, &filter_symbol.argv)) {
		grad_argcv_free(filter_symbol.argc, filter_symbol.argv);
		filter_symbol.argc = 0;
	}
	return 0;
}

static int
error_log_handler(int argc, cfg_value_t *argv,
		  void *block_data, void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	if (strcmp(argv[1].v.string, "none") == 0)
		filter_symbol.errfile = NULL;
	else if (argv[1].v.string[0] == '/')
		filter_symbol.errfile = argv[1].v.string;
	else {
		char *p = grad_mkfilename(grad_log_dir, argv[1].v.string);
		filter_symbol.errfile = cfg_malloc(strlen(p)+1, NULL);
		strcpy(filter_symbol.errfile, p);
		grad_free(p);
	}
	return 0;
}

static int
_store_format_ptr(int argc, cfg_value_t *argv, void *block_data,
		  void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	* (char**) handler_data = argv[1].v.string;
	return 0;
}

static struct cfg_stmt filter_auth_stmt[] = {
	{ "input-format", CS_STMT, NULL,
	  _store_format_ptr, &filter_symbol.descr[R_AUTH].input_fmt,
	  NULL, NULL },
	{ "wait-reply", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.descr[R_AUTH].wait_reply,
	  NULL, NULL },
	{ "success-on-failure", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.descr[R_AUTH].on_fail,
	  NULL, NULL },
	{ NULL },
};

static struct cfg_stmt filter_acct_stmt[] = {
	{ "input-format", CS_STMT, NULL,
	  _store_format_ptr, &filter_symbol.descr[R_ACCT].input_fmt,
	  NULL, NULL },
	{ "wait-reply", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.descr[R_ACCT].wait_reply,
	  NULL, NULL },
	{ "success-on-failure", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.descr[R_ACCT].on_fail,
	  NULL, NULL },
	{ NULL },
};

/* Configuration issues */
static struct cfg_stmt filter_stmt[] = {
	{ "exec-path", CS_STMT, NULL, exec_path_handler, NULL, NULL, NULL },
	{ "error-log", CS_STMT, NULL, error_log_handler, NULL, NULL, NULL },
	{ "auth", CS_BLOCK, NULL, NULL, NULL, filter_auth_stmt, NULL },
	{ "acct", CS_BLOCK, NULL, NULL, NULL, filter_acct_stmt, NULL },
	{ NULL },
};
	
struct cfg_stmt filters_stmt[] = {
	{ "filter", CS_BLOCK, NULL, filter_stmt_handler, NULL, filter_stmt,
	  filter_stmt_end },
	{ NULL },
};
