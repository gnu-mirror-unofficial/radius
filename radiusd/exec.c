/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
  
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

#define RADIUS_MODULE_EXEC_C
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
#include <syslog.h>
#include <radiusd.h>
#include <obstack1.h>
#include <argcv.h>
#include <symtab.h>
#include <rewrite.h>

struct cleanup_data {
	VALUE_PAIR **vp;
	FILE *fp;
	pid_t pid;
};

void
rad_exec_cleanup(arg)
	void *arg;
{
	struct cleanup_data *p = arg;

	fclose(p->fp);
	avl_free(*p->vp);
	kill(p->pid, SIGKILL);
}

int
radius_change_uid(pwd)
	struct passwd *pwd;
{
	if (pwd->pw_gid != 0 && setgid(pwd->pw_gid)) {
		radlog(L_ERR|L_PERROR,
		       _("setgid(%d) failed"), pwd->pw_gid);
	}
	if (pwd->pw_uid != 0) {
#if defined(HAVE_SETEUID)
		if (seteuid(pwd->pw_uid)) 
			radlog(L_ERR|L_PERROR,
			       _("seteuid(%d) failed (ruid=%d, euid=%d)"),
			       pwd->pw_uid, getuid(), geteuid());
#elif defined(HAVE_SETREUID)
		if (setreuid(0, pwd->pw_uid)) 
			radlog(L_ERR|L_PERROR,
			       _("setreuid(0,%d) failed (ruid=%d, euid=%d)"),
			       pwd->pw_uid, getuid(), geteuid());
#else
# error "*** NO WAY TO SET EFFECTIVE UID IN radius_change_uid() ***"
#endif
	}
}

struct exec_sigchild_data {
	pid_t pid;
	int status;
};

int
exec_sigchild(pid, status, data)
	pid_t pid;
	int status;
	void *data;
{
	struct exec_sigchild_data *dp = data;
	if (dp->pid == pid) {
		dp->pid = 0;
		dp->status = status;
		return 1;
	}
	return 0;
}

/* Execute a program on successful authentication.
   Return 0 if exec_wait == 0.
   Return the exit code of the called program if exec_wait != 0.
   NOTE: The routine relies upon SIGCHLD being set ti SIG_IGN and
   SIGPIPE being set to SIG_DFL. */
int
radius_exec_program(cmd, req, reply, exec_wait, user_msg)
        char *cmd;
        RADIUS_REQ *req;
        VALUE_PAIR **reply;
        int exec_wait;
        char **user_msg;
{
        int p[2];
        int n;
	pid_t pid;
	int status;
        char *ptr, *errp;
        VALUE_PAIR *vp;
        FILE *fp;
        int line_num;
        char buffer[RAD_BUFFER_SIZE];
        struct passwd *pwd;
        struct cleanup_data cleanup_data;
	sigset_t sigset;
	
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
        }
	
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	
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
                }

                for (n = getmaxfd(); n >= 3; n--)
                        close(n);

                chdir("/tmp");

                radius_change_uid(pwd);
		
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
	
	cleanup_data.vp = &vp;
	cleanup_data.fp = fp;
	cleanup_data.pid = pid;
	pthread_cleanup_push(rad_exec_cleanup, &cleanup_data);
	
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

	sigwait(&sigset, &n);
        while (waitpid(pid, &status, 0) != pid)
		;
	
	pthread_cleanup_pop(0);
	pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        fclose(fp);

        if (vp) 
                avl_merge(reply, &vp);

        if (WIFEXITED(status)) {
                status = WEXITSTATUS(status);
                debug(1, ("returned: %d", status));
                if (status == 2) {
                        radlog(L_ERR,
                               _("can't run external program (reason reported via syslog channel user.err)"));
                }
                return status;
        }
        radlog(L_ERR, _("radius_exec_program(): abnormal child exit"));

        return 1;
}

pid_t
radius_run_filter(argc, argv, errfile, p)
	int  argc;
	char **argv;
	char *errfile;
	int  *p;
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
		i = open(errfile, O_CREAT|O_WRONLY, 0644);
                if (i > 0 && i != 2) {
                        dup2(i, 2);
			close(i);
		}
		
		/* Close unneded descripitors */
		for (i = getmaxfd(); i > 2; i--)
			close(i);

		radius_change_uid(pwd);
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

void
radius_close_filter(pid, pipe)
	pid_t pid;
	int *pipe;
{
	close(pipe[0]);
	close(pipe[1]);
	kill(pid, SIGTERM);
}

typedef struct filter_symbol Filter_symbol;
typedef struct filter_runtime_data Filter;

struct filter_runtime_data {
	Filter *next;
	Filter_symbol *sym;
	pthread_t tid;              /* Thread ID of the thread this filter
				       belongs to */
	pid_t  pid;                 /* Pid of the filter process */
	size_t lines_input;         /* Number of lines read from the filter */
	size_t lines_output;        /* Number of lines written to the filter */
	FILE   *input;              /* Input stream */
	FILE   *output;             /* Output stream */
};

struct filter_symbol {
        struct user_symbol *next;
	char *name;                 /* Name of the filter */
	/* Configuration data */
	int line_num;               /* Number of line in raddb/config where
				       the filter is defined */
	int  argc;                  /* Number of entries in the argv */
        char **argv;                /* Invocation vector */
	char *errfile;              /* Filename for error output (fd 2) */
	int common;                 /* Is the filter common for all threads */
	struct {
		char *input_fmt;    
		int wait_reply;
	} auth, acct;
	
	Filter *filter;             /* Runtime data */
	pthread_mutex_t mutex;      /* Prevent concurrent access */
}; 

static Symtab *filter_tab;
static Filter_symbol filter_symbol;

struct filter_sigchild_data {
	pid_t pid;
	int status;
};

static void filter_lock(Filter *filter);
static void filter_unlock(Filter *filter);
static void filter_close(Filter *filter);
static Filter *filter_open(char *name, RADIUS_REQ *req);
static char *filter_xlate(struct obstack *sp, char *fmt, RADIUS_REQ *radreq);
static int filter_write(Filter *filter, char *fmt, RADIUS_REQ *radreq);
static int filter_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
			       void *handler_data);
static int filter_stmt_end(void *block_data, void *handler_data);
static int exec_path_handler(int argc, cfg_value_t *argv, void *block_data,
			     void *handler_data);
static int error_log_handler(int argc, cfg_value_t *argv, void *block_data,
			     void *handler_data);
static int _store_format_ptr(int argc, cfg_value_t *argv, void *block_data,
			     void *handler_data);

static int
_close_filter(data, sym)
	struct filter_sigchild_data *data;
	Filter_symbol *sym;
{
	Filter *filter;

	for (filter = sym->filter; filter; filter = filter->next) {
		if (filter->pid == data->pid) {
			if (filter->input) {
				fclose(filter->input);
				filter->input = NULL;
			}
			if (filter->output) {
				fclose(filter->output);
				filter->output = NULL;
			}
			radlog(L_ERR,
	      _("filter %s (pid %d) exited with status %d (in: %u, out: %u)"),
			       sym->name, filter->pid,
			       WEXITSTATUS(data->status),
			       filter->lines_input, filter->lines_output);
			filter->pid = -1;
			data->pid = 0;
			return 1;
		}
	}
	return 0;
}

static void
filter_lock(filter)
	Filter *filter;
{
	if (filter->sym->common)
		Pthread_mutex_lock(&filter->sym->mutex);
}

static void
filter_unlock(filter)
        Filter *filter;
{
	if (filter->sym->common)
		Pthread_mutex_unlock(&filter->sym->mutex);
}

int
filter_sigchild(pid, status)
	pid_t pid;
	int status;
{
	struct filter_sigchild_data data;
	data.pid = pid;
	data.status = status;
	symtab_iterate(filter_tab, _close_filter, &data);
	return data.pid;
}
	
void
filter_close(filter)
	Filter *filter;
{
	if (filter->pid == -1) 
		return;

	if (filter->input) {
		fclose(filter->input);
		filter->input = NULL;
	}
	if (filter->output) {
		fclose(filter->output);
		filter->output = NULL;
	}
	kill(filter->pid, SIGTERM);
	filter->pid = -1;
}

static Filter *
filter_open(name, req)
	char *name;
	RADIUS_REQ *req;
{
	Filter *filter;
	Filter_symbol *sym = sym_lookup(filter_tab, name);
	if (!sym) {
		radlog_req(L_ERR, req,
			   _("filter %s is not declared"),
			   name);
		return NULL;
	}

	pthread_mutex_lock(&sym->mutex);
	if (!sym->common) {
		pthread_t tid = pthread_self();
		for (filter = sym->filter; filter; filter = filter->next) 
			if (filter->tid == tid)
				break;
	} else
		filter = sym->filter;
	if (!filter) {
		filter = alloc_entry(sizeof(*filter));
		filter->tid = pthread_self();
		filter->sym = sym;
		filter->next = sym->filter;
		sym->filter = filter;
	}
	
	if (filter->pid <= 0) {
		int pipe[2];
		filter->pid = radius_run_filter(sym->argc, sym->argv,
						sym->errfile,
						pipe);
		if (filter->pid < 0) {
			radlog_req(L_ERR|L_PERROR, req,
				   _("cannot run filter %s"),
				   name);
			pthread_mutex_unlock(&sym->mutex);
			return NULL;
		}

		if (!sym->auth.wait_reply && !sym->acct.wait_reply) {
			close(pipe[0]);
			filter->input = NULL;
		} else
			filter->input  = fdopen(pipe[0], "r");
		filter->output = fdopen(pipe[1], "w");
		filter->lines_input = 0;
		filter->lines_output = 0; 
	}

	if (kill(filter->pid, 0)) {
		radlog_req(L_ERR|L_PERROR, req,
			   _("filter %s"),
			   name);
		filter_close(filter);
		filter = NULL;
	}
	pthread_mutex_unlock(&sym->mutex);

	return filter;
}

static void
cleanup_obstack(arg)
	void *arg;
{
	struct obstack *stk = arg;
	obstack_free(stk, NULL);
}

static char *
filter_xlate(sp, fmt, radreq)
	struct obstack *sp;
	char *fmt;
	RADIUS_REQ *radreq;
{
	char *str;
	if (fmt[0] == '=') {
		Datatype type;
		Datum datum;
		
		if (interpret(fmt+1, radreq, &type, &datum)) 
			return NULL;
		if (type != String) {
			radlog(L_ERR, "%s: %s",
			       fmt+1, _("wrong return type"));
			return NULL;
		}
		obstack_grow(sp, datum.sval, strlen(datum.sval)+1);
		free_string(datum.sval);
		str = obstack_finish(sp);
	} else {
		str = radius_xlate(sp, fmt, radreq, NULL);
	}
	return str;
}

static int
filter_write(filter, fmt, radreq)
	Filter *filter;
	char *fmt;
	RADIUS_REQ *radreq;
{
	int rc, length;
	struct obstack stack;
	char *str;
	
	if (!fmt)
		return -1;
	
	obstack_init(&stack);
	pthread_cleanup_push(cleanup_obstack, &stack);
	str = filter_xlate(&stack, fmt, radreq);
	if (!str) {
		rc = length = 0;
	} else {
		length = strlen(str);
		debug(1,("%s < \"%s\"", filter->sym->name, str));
		rc = fprintf(filter->output, "%s\n", str);
		fflush(filter->output);
	}
	pthread_cleanup_pop(1);
	filter->lines_output++;
	return rc != length + 1;
}

/* Interface triggered by Auth-External-Filter.
   Returns: 0   -- Authentication succeeded
            !0  -- Authentication failed */
int
filter_auth(name, req, reply_pairs)
	char *name;
	RADIUS_REQ *req;
	VALUE_PAIR **reply_pairs;
{
	Filter *filter;
	int rc = -1;

	filter = filter_open(name, req);
	if (!filter)
		return -1;
	pthread_cleanup_push((void (*)(void)) filter_unlock, filter);
	filter_lock(filter);
	if (filter->pid == -1)
		rc = -1;
	else if (filter_write(filter, filter->sym->auth.input_fmt, req)) 
		rc = -1;
	else if (!filter->sym->auth.wait_reply) 
		rc = 0;
	else {
		char *buf = NULL;
		char buffer[1024];
	
        	pthread_cleanup_push((void (*)(void)) filter_close, filter);
		buf = fgets(buffer, sizeof buffer, filter->input);
		pthread_cleanup_pop(0);
		if (!buf) {
			radlog(L_ERR|L_PERROR,
		       	       _("reading from filter %s"),
		       	       filter->sym->name);
			rc = -1;
		} else {
			filter->lines_input++;
			if (isdigit(*buf)) {
				char *ptr;
				VALUE_PAIR *vp = NULL;
				char *errp;

                		debug(1, ("%s > \"%s\"", filter->sym->name,
					  buffer));
				rc = strtoul(buf, &ptr, 0);
				if (userparse(ptr, &vp, &errp)) {
					radlog(L_ERR,
				       		_("<stdout of %s>:%d: %s"),
					       filter->sym->name,
					       filter->lines_output,
					       errp);
					avl_free(vp);
				} else
                			avl_merge(reply_pairs, &vp);
			} else {
				radlog(L_ERR,
				       _("filter %s (auth): bad output: %s"),
					 filter->sym->name, buf);
				rc = -1;
			}
		}
	}

	pthread_cleanup_pop(1);
	return rc;
}

int
filter_acct(name, req)
	char *name;
	RADIUS_REQ *req;
{
	Filter *filter;
	int rc = -1;
	char *buf = NULL;
	char *errp;
	size_t size;
	VALUE_PAIR *vp = NULL;
	char buffer[1024];
	
	filter = filter_open(name, req);
	if (!filter)
		return -1;
	pthread_cleanup_push((void (*)(void)) filter_unlock, filter);
	filter_lock(filter);
	if (filter->pid == -1)
		rc = -1;
	else if (filter_write(filter, filter->sym->acct.input_fmt, req)) 
		rc = -1;
	else if (!filter->sym->acct.wait_reply) 
		rc = 0;
	else {
		char *buf = NULL;
		char buffer[1024];
	
                pthread_cleanup_push((void (*)(void)) filter_close, filter);
		buf = fgets(buffer, sizeof buffer, filter->input);
		pthread_cleanup_pop(0);
		if (!buf) {
			radlog(L_ERR|L_PERROR,
		       	       _("reading from filter %s"),
		       	       filter->sym->name);
			rc = -1;
		} else {
			filter->lines_input++;
			if (isdigit(*buf)) {
				char *ptr;
				char *errp;

				debug(1, ("%s > \"%s\"",
					  filter->sym->name, buffer));
				rc = strtoul(buf, &ptr, 0);
			} else {
				radlog(L_ERR,
				       _("filter %s (acct): bad output: %s"),
				       filter->sym->name, buf);
				rc = -1;
			}
		}
	}

	pthread_cleanup_pop(1);
	return rc;
}
	
static int
free_symbol_entry(sym)
        Filter_symbol *sym;
{
	Filter *filter;
	efree(sym->auth.input_fmt);
	efree(sym->acct.input_fmt);
	argcv_free(sym->argc, sym->argv);
	efree(sym->errfile);
	filter = sym->filter;
	while (filter) {
		Filter *next = filter->next;
		if (filter->pid > 0)
			filter_close(filter);
		free_entry(filter);
		filter = next;
	}
	pthread_mutex_destroy(&sym->mutex);
	return 0;
}

int
filters_stmt_term(finish, block_data, handler_data)
	int finish;
	void *block_data;
	void *handler_data;
{
	if (!finish) {
		if (filter_tab)
			symtab_clear(filter_tab);
		else
			filter_tab = symtab_create(sizeof(Filter_symbol),
						   free_symbol_entry);
	}
	return 0;
}

static int
filter_stmt_handler(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
	filter_symbol.auth.wait_reply = 1;
	filter_symbol.acct.wait_reply = 1;
	filter_symbol.common = 0;
	return 0;
}

static int
filter_stmt_end(block_data, handler_data)
	void *block_data;
	void *handler_data;
{
	if (filter_symbol.argc) {
		Filter_symbol *sym = sym_lookup_or_install(filter_tab,
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
		sym->auth.input_fmt = estrdup(filter_symbol.auth.input_fmt);
		sym->acct.input_fmt = estrdup(filter_symbol.acct.input_fmt);
		sym->auth.wait_reply = filter_symbol.auth.wait_reply;
		sym->acct.wait_reply = filter_symbol.acct.wait_reply;
		sym->errfile  = estrdup(filter_symbol.errfile);
		sym->common   = filter_symbol.common;
		sym->filter = NULL;
		pthread_mutex_init(&sym->mutex, NULL);
	}
	return 0;
}

static int
exec_path_handler(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
error_log_handler(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
_store_format_ptr(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
	  _store_format_ptr, &filter_symbol.auth.input_fmt, NULL, NULL },
	{ "wait-reply", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.auth.wait_reply, NULL, NULL },
	{ NULL },
};

static struct cfg_stmt filter_acct_stmt[] = {
	{ "input-format", CS_STMT, NULL,
	  _store_format_ptr, &filter_symbol.acct.input_fmt, NULL, NULL },
	{ "wait-reply", CS_STMT, NULL,
	  cfg_get_boolean, &filter_symbol.acct.wait_reply, NULL, NULL },
	{ NULL },
};

/* Configuration issues */
static struct cfg_stmt filter_stmt[] = {
	{ "exec-path", CS_STMT, NULL, exec_path_handler, NULL, NULL, NULL },
	{ "error-log", CS_STMT, NULL, error_log_handler, NULL, NULL, NULL },
	{ "common", CS_STMT, NULL, cfg_get_boolean, &filter_symbol.common,
	  NULL, NULL },
	{ "auth", CS_BLOCK, NULL, NULL, NULL, filter_auth_stmt, NULL },
	{ "acct", CS_BLOCK, NULL, NULL, NULL, filter_acct_stmt, NULL },
	{ NULL },
};
	
struct cfg_stmt filters_stmt[] = {
	{ "filter", CS_BLOCK, NULL, filter_stmt_handler, NULL, filter_stmt,
	  filter_stmt_end },
	{ NULL },
};
