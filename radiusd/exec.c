/* This file is part of GNU Radius.
   Copyright (C) 2002,2003 Free Software Foundation, Inc.

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

#define RADIUS_MODULE_EXEC_C

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
#include <obstack1.h>
#include <argcv.h>
#include <symtab.h>
#include <rewrite.h>

int
radius_change_uid(struct passwd *pwd)
{
	if (pwd->pw_gid != 0 && setgid(pwd->pw_gid)) {
		radlog(L_ERR|L_PERROR,
		       _("setgid(%d) failed"), pwd->pw_gid);
		return -1;
	}
	if (pwd->pw_uid != 0) {
#if defined(HAVE_SETEUID)
		if (seteuid(pwd->pw_uid)) {
			radlog(L_ERR|L_PERROR,
			       _("seteuid(%d) failed (ruid=%d, euid=%d)"),
			       pwd->pw_uid, getuid(), geteuid());
			return -1;
		}
#elif defined(HAVE_SETREUID)
		if (setreuid(0, pwd->pw_uid)) {
			radlog(L_ERR|L_PERROR,
			       _("setreuid(0,%d) failed (ruid=%d, euid=%d)"),
			       pwd->pw_uid, getuid(), geteuid());
			return -1;
		}
#else
# error "*** NO WAY TO SET EFFECTIVE UID IN radius_change_uid() ***"
#endif
	}
	return 0;
}

/* Execute a program on successful authentication.
   Return 0 if exec_wait == 0.
   Return the exit code of the called program if exec_wait != 0. */
int
radius_exec_program(char *cmd, RADIUS_REQ *req, VALUE_PAIR **reply,
		    int exec_wait)
{
        int p[2];
        int n;
        char *ptr, *errp;
        VALUE_PAIR *vp;
        FILE *fp;
        int line_num;
        char buffer[RAD_BUFFER_SIZE];
        struct passwd *pwd;
	pid_t pid;
	int status;
	RETSIGTYPE (*oldsig)();
	
        if (cmd[0] != '/') {
                radlog(L_ERR,
   _("radius_exec_program(): won't execute, not an absolute pathname: %s"),
                       cmd);
                return -1;
        }

        /* Check user/group
           FIXME: This should be checked *once* after re-reading the
           configuration */
        pwd = getpwnam(exec_user);
        if (!pwd) {
                radlog(L_ERR,
    _("radius_exec_program(): won't execute, no such user: %s"),
                       exec_user);
                return -1;
        }

        if (exec_wait) {
                if (pipe(p) != 0) {
                        radlog(L_ERR|L_PERROR, _("couldn't open pipe"));
                        return -1;
                }
		if ((oldsig = rad_set_signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
			radlog(L_ERR|L_PERROR, _("can't reset SIGCHLD"));
			return -1;
		}
        } 

        if ((pid = fork()) == 0) {
                int argc;
                char **argv;
                struct obstack s;

                obstack_init(&s);
                
                /* child branch */
                ptr = radius_xlate(&s, cmd, req, reply ? *reply : NULL);

                debug(1, ("command line: %s", ptr));

                argcv_get(ptr, "", &argc, &argv);
                
                if (exec_wait) {
                        if (close(p[0]))
                                radlog(L_ERR|L_PERROR, _("can't close pipe"));
                        if (dup2(p[1], 1) != 1)
                                radlog(L_ERR|L_PERROR, _("can't dup stdout"));
                } else
			close(1);

                for (n = getmaxfd(); n >= 3; n--)
                        close(n);

                chdir("/tmp");

                if (radius_change_uid(pwd))
			exit(2);
		
                execvp(argv[0], argv);

                /* Report error via syslog: we might not be able
		   to restore initial privileges if we were started
		   as non-root. */
                openlog("radiusd", LOG_PID, LOG_USER);
                syslog(LOG_ERR, "can't run %s (ruid=%d, euid=%d): %m",
                       argv[0], getuid(), geteuid());
                exit(2);
        }

        /* Parent branch */ 
        if (pid < 0) {
                radlog(L_ERR|L_PERROR, "fork");
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
                debug(1, ("got `%s'", buffer));
                if (userparse(ptr, &vp, &errp)) {
                        radlog(L_ERR,
			       _("<stdout of %s>:%d: %s"),
			       cmd, line_num, errp);
                        avl_free(vp);
                        vp = NULL;
                }
        }

        fclose(fp);

	waitpid(pid, &status, 0);
	if (rad_set_signal(SIGCHLD, oldsig) == SIG_ERR)
		radlog(L_CRIT|L_PERROR,
			_("can't restore SIGCHLD"));

        if (WIFEXITED(status)) {
                status = WEXITSTATUS(status);
                debug(1, ("returned: %d", status));
                if (status == 2) {
                        radlog(L_ERR,
                               _("can't run external program `%s' (reason reported via syslog channel user.err)"),
			       cmd);
                }
        } else {
		format_exit_status(buffer, sizeof buffer, status);
		
		radlog(L_ERR,
		       _("external program `%s' %s"), cmd, buffer);
	}

        if (vp && reply) 
                avl_merge(reply, &vp);
	avl_free(vp);

        return status;
}

pid_t
radius_run_filter(int argc, char **argv, char *errfile, int *p)
{
	pid_t  pid;
	int    rightp[2], leftp[2];
	struct passwd *pwd;
	int i;

        pwd = getpwnam(exec_user);
        if (!pwd) {
                radlog(L_ERR,
		       _("won't execute, no such user: %s"),
                       exec_user);
                return -1;
        }

	pipe(leftp);
	pipe(rightp);
    
	switch (pid = fork()) {

		/* The child branch.  */
	case 0:
		/* attach the pipes */

		/* Right-end */
		close(1);
		dup2(rightp[1], 1);
		close(rightp[0]); 

		/* Left-end */
		close(0);
		dup2(leftp[0], 0);
		close(leftp[1]);

		/* Error output */
		i = open(errfile, O_CREAT|O_WRONLY|O_APPEND, 0644);
                if (i > 0 && i != 2) {
                        dup2(i, 2);
			close(i);
		}
		
		/* Close unneded descripitors */
		for (i = getmaxfd(); i > 2; i--)
			close(i);

		if (radius_change_uid(pwd))
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

static Symtab *filter_tab;

struct cleanup_info {
	pid_t pid;
	int status;
};
	
static int
filter_cleanup_proc(void *ptr, Filter *filter)
{
	struct cleanup_info *info = ptr;

	if (filter->pid == info->pid) {
		static char buffer[512];
		
		format_exit_status(buffer, sizeof buffer, info->status);
		radlog(L_ERR,
		       _("filter %s (pid %d) %s (in: %u, out: %u)"),
		       filter->name, filter->pid,
		       buffer,
		       filter->lines_input, filter->lines_output);
		filter->pid = 0;
		return 1;
	}
	return 0;
}

void
filter_cleanup(pid_t pid, int status)
{	
	struct cleanup_info info;
	info.pid = pid;
	info.status = status;
	symtab_iterate(filter_tab, filter_cleanup_proc, &info);
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
filter_open(char *name, RADIUS_REQ *req, int type, int *errp)
{
	Filter *filter = sym_lookup(filter_tab, name);
	if (!filter) {
		radlog_req(L_ERR, req,
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
			radlog_req(L_ERR|L_PERROR, req,
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
		radlog_req(L_ERR|L_PERROR, req, _("filter %s"), name);
		filter_close(filter);
		filter = NULL;
	}

	return filter;
}

static char *
filter_xlate(struct obstack *sp, char *fmt, RADIUS_REQ *radreq)
{
	char *str;
	
	if (fmt[0] == '=') {
		Datatype type;
		Datum datum;

		/*FIXME: Should be compiled!*/
		if (rewrite_interpret(fmt+1, radreq, &type, &datum)) 
			return NULL;
		if (type != String) {
			radlog(L_ERR, "%s: %s",
			       fmt+1, _("wrong return type"));
			return NULL;
		}
		obstack_grow(sp, datum.sval, strlen(datum.sval)+1);
		efree(datum.sval);
		str = obstack_finish(sp);
	} else {
		str = radius_xlate(sp, fmt, radreq, NULL);
	}
	return str;
}

static int
filter_write(Filter *filter, char *fmt, RADIUS_REQ *radreq)
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
		debug(1,("%s < \"%s\"", filter->name, str));
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
filter_auth(char *name, RADIUS_REQ *req, VALUE_PAIR **reply_pairs)
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
			radlog(L_ERR|L_PERROR,
		       	       _("reading from filter %s"),
		       	       filter->name);
			filter_close(filter);
			rc = err;
		} else if (isdigit(buffer[0])) {
			char *ptr;
			VALUE_PAIR *vp = NULL;
			char *errp;

			debug(1, ("%s > \"%s\"", filter->name, buffer));
			rc = strtoul(buffer, &ptr, 0);
			if (userparse(ptr, &vp, &errp)) {
				radlog(L_ERR,
				       _("<stdout of %s>:%d: %s"),
				       filter->name,
				       filter->lines_output,
				       errp);
				avl_free(vp);
			} else 
				avl_merge(reply_pairs, &vp);
		} else {
			radlog(L_ERR,
			       _("filter %s (auth): bad output: %s"),
			       filter->name, buffer);
			rc = err;
		}
	}

	return rc;
}

int
filter_acct(char *name, RADIUS_REQ *req)
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
			radlog(L_ERR|L_PERROR,
		       	       _("reading from filter %s"),
		       	       filter->name);
			rc = err;
			filter_close(filter);
		} else if (isdigit(buffer[0])) {
			char *ptr;

			debug(1, ("%s > \"%s\"", filter->name, buffer));
			rc = strtoul(buffer, &ptr, 0);
			if (!isspace(*ptr)) {
				radlog(L_ERR,
				       _("filter %s (acct): bad output: %s"),
				       filter->name, buffer);
				return -1;
			}
		} else {
			radlog(L_ERR,
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
	efree(filter->descr[R_AUTH].input_fmt);
	efree(filter->descr[R_ACCT].input_fmt);
	argcv_free(filter->argc, filter->argv);
	efree(filter->errfile);
	if (filter->pid > 0)
		filter_close(filter);
	return 0;
}

int
filters_stmt_term(int finish, void *block_data, void *handler_data)
{
	if (!finish) {
		if (filter_tab)
			symtab_clear(filter_tab);
		else
			filter_tab = symtab_create(sizeof(Filter),
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
		Filter *sym = sym_lookup_or_install(filter_tab,
						    filter_symbol.name,
						    1);
		if (sym->argc) {
			radlog(L_ERR,
			       _("%s:%d: filter already declared at %s:%d"),
			       cfg_filename, cfg_line_num,
			       cfg_filename, sym->line_num);
			return 0;
		}

		sym->line_num = filter_symbol.line_num;
		sym->argc     = filter_symbol.argc;
		sym->argv     = filter_symbol.argv;
		sym->descr[R_AUTH].input_fmt =
			estrdup(filter_symbol.descr[R_AUTH].input_fmt);
		sym->descr[R_ACCT].input_fmt =
			estrdup(filter_symbol.descr[R_ACCT].input_fmt);
		sym->descr[R_AUTH].wait_reply =
			filter_symbol.descr[R_AUTH].wait_reply;
		sym->descr[R_ACCT].wait_reply =
			filter_symbol.descr[R_ACCT].wait_reply;
		sym->descr[R_AUTH].on_fail =
			!filter_symbol.descr[R_AUTH].on_fail;
		sym->descr[R_ACCT].on_fail =
			!filter_symbol.descr[R_ACCT].on_fail;
		sym->errfile  = estrdup(filter_symbol.errfile);
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
	
	if (argcv_get(argv[1].v.string, "",
		      &filter_symbol.argc, &filter_symbol.argv)) {
		argcv_free(filter_symbol.argc, filter_symbol.argv);
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
		char *p = mkfilename(radlog_dir, argv[1].v.string);
		filter_symbol.errfile = cfg_malloc(strlen(p)+1, NULL);
		strcpy(filter_symbol.errfile, p);
		efree(p);
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
