/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2006,2007,2008 Free Software Foundation, Inc.

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

/* RPP stands for Radius Process Pool */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include <radiusd.h>

static int rpp_stdin;
static int rpp_stdout;

/* Process intercommunication primitives */

enum process_status {
	process_busy,      /* Process is busy handling a request */
	process_ready,     /* Precess is idle and ready for input */
	process_finished   /* Process has finished */
};

typedef struct {
	pid_t pid;    /* PID of the handler process */
	int p[2];     /* IPC descriptors. p[0] - input, p[1] - output */
	enum process_status status; /* Current process status */
	int exit_status;  /* Process exit status if status==process_finished */
} rpp_proc_t;


/* Low-level calls */

/* Write into the pipe (represented by FD) SIZE bytes from PTR. TV
   sets timeout. TV==NULL means no timeout is imposed.

   Returns number of bytes written */
static int
pipe_write(int fd, void *ptr, size_t size, struct timeval *tv)
{
	errno = 0;
	if (!tv)
		return write(fd, ptr, size);
	else {
		char *data = ptr;
		int rc;
		struct timeval tval, start;
		fd_set wr_set;
		size_t n;

		gettimeofday(&start, NULL);
		for (n = 0; n < size;) {

			FD_ZERO(&wr_set);
			FD_SET(fd, &wr_set);

			tval = *tv;
			if (grad_recompute_timeout (&start, &tval)) {
				errno = ETIMEDOUT;
				break;
			}
			
			rc = select(fd + 1, NULL, &wr_set, NULL, &tval);
			if (rc == 0) {
				errno = ETIMEDOUT;
				GRAD_DEBUG(100, "rc = 0");
				break;
			} else if (rc < 0) {
				if (errno == EINTR) 
					continue;
				GRAD_DEBUG2(100, "rc = %d, errno = %d", 
                                            rc, errno);
				break;
			} else if (rc > 0) {
				rc = write(fd, data, 1);
				if (rc != 1) {
					GRAD_DEBUG2(100, "rc = %d, errno = %d", 
                                                    rc, errno);
					break;
				}
				data++;
				n++;
			}
		}
		GRAD_DEBUG1(100,"n = %d",n);
		return n;
	}
}

/* Read from the pipe (represented by FD) at most SIZE bytes into PTR. TV
   sets timeout. TV==NULL means no timeout is imposed.

   Returns number of bytes read */
static int
pipe_read(int fd, void *ptr, size_t size, struct timeval *tv)
{
	char *data = ptr;
	int rc;

	errno = 0;
	if (!tv) {
		int rdbytes = 0;
		do {
			rc = read(fd, data, size);
			if (rc > 0) {
				data += rc;
				size -= rc;
				rdbytes += rc;
			} else if (errno != EINTR)
				break;
		} while (size > 0);
		return rdbytes;
	} else {
		struct timeval tval, start;
		fd_set rd_set;
		size_t n;
		
		gettimeofday(&start, NULL);
		for (n = 0; n < size;) {

			FD_ZERO(&rd_set);
			FD_SET(fd, &rd_set);

			tval = *tv;
			if (grad_recompute_timeout (&start, &tval)) {
				errno = ETIMEDOUT;
				break;
			}

			rc = select(fd + 1, &rd_set, NULL, NULL, &tval);
			if (rc == 0) {
				errno = ETIMEDOUT;
				break;
			}
			if (rc < 0) {
				if (errno == EINTR)
					continue;
				break;
			} else if (rc > 0) {
				rc = read(fd, data, 1);
				if (rc != 1) 
					break;
				data++;
				n++;
			}
		}
		return n;
	}
}


/* RPP layer I/O. Each packet transmitted over a pipe is preceeded by
   its length (a size_t number in host order) */

/* Read SIZE bytes from the pipe (FD) into DATA. TV sets timeout */
static int
rpp_fd_read(int fd, void *data, size_t size, struct timeval *tv)
{
	size_t sz, nbytes = 0;

	sz = pipe_read(fd, &nbytes, sizeof(nbytes), tv);
	if (sz == 0)
		return 0; /* eof */
	GRAD_DEBUG1(100,"nbytes=%lu",nbytes);
	if (sz != sizeof(nbytes)) 
		return -1;
	sz = nbytes > size ? size : nbytes;
	if (pipe_read (fd, data, sz, tv) != sz)
		return -2;
	for (;nbytes > size; nbytes--) {
		char c;
		if (pipe_read(fd, &c, 1, tv) != 1) 
			return -3;
	}
	
	GRAD_DEBUG1(100,"return %lu", (unsigned long)sz);
	return sz;
}

/* Write SIZE bytes from DATA to the pipe FD. TV sets timeout */
static int
rpp_fd_write(int fd, void *data, size_t size, struct timeval *tv)
{
	int rc;
	GRAD_DEBUG1(100,"size=%lu",size);
	if (pipe_write(fd, &size, sizeof(size), tv) != sizeof(size)) 
		return -1;
	if (pipe_write(fd, data, size, tv) != size) 
		return -2;
	GRAD_DEBUG1(1,"return %lu", (unsigned long)size);
	return size;
}



/* Start a handler process. PROC_MAIN is the handler function (process'
   main loop). DATA is passed to PROC_MAIN verbatim.

   On success return 0 and fill in PROC structure. */
int
rpp_start_process(rpp_proc_t *proc, int (*proc_main)(void *), void *data)
{
	int inp[2];
	int outp[2];
	pid_t pid;
	
	if (pipe(inp)) {
		grad_log(GRAD_LOG_ERR, "pipe(inp): %s", strerror(errno));
		return -1;
	}
	
	if (pipe(outp)) {
		grad_log (GRAD_LOG_ERR, "pipe(outp): %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		grad_log (GRAD_LOG_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* Child */
		/* Close remote side of pipes */
		close(inp[0]);
		close(outp[1]);
		/* Close stdin */
		close(0);
		/* Redirect stdout to stderr */
		dup2(2, 1);

		rpp_stdin = outp[0];
		rpp_stdout = inp[1];
		
		/* Run the main process */
		exit(proc_main(data));
	}

	/* Parent */
	close (inp[1]);
	close (outp[0]);

	proc->pid = pid;
	proc->p[0] = inp[0];
	proc->p[1] = outp[1];
	proc->status = process_ready;
	return 0;
}

  

static grad_list_t *process_list; /* List of rpp_proc_t */

/* Look up the rpp_proc_t whose input descriptor is FD */
rpp_proc_t *
rpp_lookup_fd(int fd)
{
	rpp_proc_t *p;
	grad_iterator_t *itr = grad_iterator_create(process_list);
	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr))
		if (p->p[0] == fd)
			break;
	grad_iterator_destroy(&itr);
	return p;
}

/* Find an rpp_proc_t ready for handling the reqest. If none is found,
   start a new one. PROC_MAIN and DATA have the same meaning as in
   rpp_start_process() */
rpp_proc_t *
rpp_lookup_ready(int (*proc_main)(void *), void *data)
{
	rpp_proc_t *p;

	if (process_list) {
		grad_iterator_t *itr = grad_iterator_create(process_list);
		for (p = grad_iterator_first(itr);
		     p && p->status != process_ready;
		     p = grad_iterator_next(itr))
			;
		grad_iterator_destroy(&itr);
	} else {
		process_list = grad_list_create();
		p = NULL;
	}
	
	if (!p) {
		rpp_proc_t proc;
		if (grad_list_count(process_list) == max_children) 
			return NULL;
		if (rpp_start_process(&proc, proc_main, data)) 
			return NULL;
		radiusd_register_input_fd("rpp", proc.p[0], NULL);
		p = grad_emalloc(sizeof(*p));
		*p = proc;
		grad_list_append(process_list, p);
	}
	return p;
}

/* Find the rpp_proc_t with a given PID */
static int
rpp_comparator(const void *item, const void *data)
{
	const rpp_proc_t *p = item;
	const pid_t *pid = data;
	return p->pid != *pid;
}

/* NOTE: Do not use any memory allocation calls */
rpp_proc_t *
rpp_lookup_pid(pid_t pid)
{
	return grad_list_locate(process_list, &pid, rpp_comparator);
}

/* Remove the given rpp_proc_t from the list. The underlying process
   is supposed to have finished. No diagnostics is output. */
static void
_rpp_remove(rpp_proc_t *p)
{
	close(p->p[0]);
	close(p->p[1]);
	radiusd_close_channel(p->p[0]);
	if (grad_list_remove(process_list, p, NULL))
		grad_free(p);
}

/* Remove the given rpp_proc_t from the list. Output diagnostics about
   exit status of the handler */
void
rpp_remove(rpp_proc_t *p)
{
	char buffer[128];
	format_exit_status(buffer, sizeof buffer, p->exit_status);
	grad_log(GRAD_LOG_NOTICE, _("child %lu %s"),
		 (unsigned long) p->pid, buffer);
	_rpp_remove(p);
}

/* Remove the rpp entry with given PID */
void
rpp_remove_pid(pid_t pid)
{
	rpp_proc_t *p = rpp_lookup_pid(pid);
	if (p)
		rpp_remove(p);
}

/* Reflect the change of state of the rpp handler process.

   The function is safe to be used from signal handlers */
void
rpp_status_changed(pid_t pid, int exit_status)
{
	rpp_proc_t *p = rpp_lookup_pid(pid);
	if (p) {
		p->status = process_finished;
		p->exit_status = exit_status;
	}
}

/* Collect rpp_proc's whose handler have exited. Free any associated
   resources */
void
rpp_collect_exited()
{
	rpp_proc_t *p;
	grad_iterator_t *itr = grad_iterator_create(process_list);
	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) {
		if (p->status == process_finished)
			rpp_remove(p);
	}
	grad_iterator_destroy(&itr);
}


static int rpp_request_handler(void *arg);

/* Return 1 if rpp with the given PID is ready for input */
int
rpp_ready(pid_t pid)
{
	if (pid == 0) {  
		if (rpp_lookup_ready(rpp_request_handler, NULL))
			return 1;
	} else {
		rpp_proc_t *p;
		grad_iterator_t *itr = grad_iterator_create(process_list);

		for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr)) {
			if (p->pid == pid) {
				break;
			}
		}
	        grad_iterator_destroy(&itr);
		if (p && p->status == process_ready)
			return 1;
	}
	return 0;
}

/* Traverse the rpp list until FUN returns non-zero or there are no
   more busy handlers. While traversing, remove finished handlers. */
void
rpp_flush(int (*fun)(void*), void *closure)
{
	time_t t;
	unsigned count;
	grad_iterator_t *itr = grad_iterator_create(process_list);

	time(&t);

	do {
		rpp_proc_t *p;
		for (count = 0, p = grad_iterator_first(itr);
		     p;
		     p = grad_iterator_next(itr))
			switch (p->status) {
			case process_ready:
				break;

			case process_busy:
				count++;
				break;

			case process_finished:
				rpp_remove (p);
			}
	} while (count > 0 && (*fun)(closure) == 0);
	grad_iterator_destroy(&itr);
}

static int
_kill_itr(void *item, void *data)
{
	rpp_proc_t *p = item;
	kill(p->pid, *(int*)data);
	return 0;
}

/* Deliver signal SIGNO to the handler with pid PID */
int
rpp_kill(pid_t pid, int signo)
{
	if (pid > 0) {
		rpp_proc_t *p = rpp_lookup_pid(pid);
		if (p) {
			kill(p->pid, signo);
			rpp_check_pid(p->pid);
		} else
     		        return 1;
	} else 
		grad_list_iterate(process_list, _kill_itr, &signo);
	return 0;
}

pid_t
rpp_check_pid(pid_t pid)
{
	int status;
	rpp_proc_t *p = rpp_lookup_pid(pid);
	if (!p)
		return -1;
	if (p->status != process_finished) {
		pid_t npid = waitpid(pid, &status, WNOHANG);
		if (npid <= 0)
			return pid;
		rpp_status_changed(pid, status);
	}
	rpp_remove (p);
	return 0;
}

/* Slay the child */
static void
_rpp_slay(rpp_proc_t *p, char *msg)
{
	grad_log(GRAD_LOG_NOTICE, _("Killing process %lu: %s"), 
                 (u_long) p->pid, msg);
	kill(p->pid, SIGKILL);
	_rpp_remove(p);
}

/* Return number of the handlers registered in the process list */
size_t
rpp_count()
{
	return grad_list_count(process_list);
}



struct rpp_request {
	int type;                    /* Request type */
	struct sockaddr_in srv_addr; /* Server address */
	struct sockaddr_in clt_addr; /* Sender address */
	int fd;                      /* Source descriptor */
	size_t size;                 /* Size of the raw data */
	/* Raw data follow */
};

#define RPP_COMPLETE  0 /* Completion reply */
#define RPP_UPDATE    1 /* Update reply */

struct rpp_reply {
	int code;
	size_t size;
	/* Data follows */
};

/* Master: Forward a request to the child */
int
rpp_forward_request(REQUEST *req)
{
	rpp_proc_t *p;
	struct rpp_request frq;
	struct timeval tv, *tvp;
	
	if (req->child_id) 
		p = rpp_lookup_pid(req->child_id);
	else
		p = rpp_lookup_ready(rpp_request_handler, NULL);

	if (!p)
		return 1;
	GRAD_DEBUG1(1, "sending request to %d", p->pid);
	
	frq.type = req->type;
	frq.srv_addr = req->srv_addr;
	frq.clt_addr = req->addr;
	frq.fd = req->fd;
	frq.size = req->rawsize;
	
	p->status = process_busy;
	req->child_id = p->pid;

	if (radiusd_write_timeout) {
		tv.tv_sec = radiusd_write_timeout;
		tv.tv_usec = 0;
		tvp = &tv;
	} else
		tvp = NULL;
	
 	if (rpp_fd_write(p->p[1], &frq, sizeof frq, tvp) != sizeof frq) {
		_rpp_slay(p, _("error writing header"));
		return 1;
	}
	if (rpp_fd_write(p->p[1], req->rawdata, req->rawsize, tvp) != req->rawsize) {
		_rpp_slay(p, _("error writing data"));
		return 1;
	}
	return 0;
}

static void
child_cleanup()
{
	pid_t pid;
	int status;
		
        for (;;) {
		pid = waitpid((pid_t)-1, &status, WNOHANG);
                if (pid <= 0)
                        break;
		filter_cleanup(pid, status);
	}
}

static RETSIGTYPE
sig_handler(int sig)
{
        switch (sig) {
	case SIGHUP:
	case SIGUSR1:
	case SIGUSR2:
		/*Ignored*/
		break;
		
	case SIGALRM:
		grad_log(GRAD_LOG_INFO, _("Child exiting on timeout."));
		/*FALLTHRU*/
		
	case SIGTERM:
	case SIGQUIT:
		/* FIXME: Possibly unsafe, it calls free() etc. */
	        radiusd_exit0();

	case SIGCHLD:
		child_cleanup();
		break;
		
	case SIGPIPE:
		/*FIXME: Any special action? */
		break;

	default:
		abort();
	}
	grad_reset_signal(sig, sig_handler);
}

/* Main loop for a child process */
int
rpp_request_handler(void *arg ARG_UNUSED)
{
	struct rpp_request frq;
	struct rpp_reply repl;
	char *data = NULL;
	size_t datasize = 0;
	REQUEST *req;

	radiusd_signal_init(sig_handler);
	grad_set_signal(SIGALRM, sig_handler);
	request_init_queue();
	
	while (1) {
		int rc;
		int len;

		alarm(process_timeout);
		len = rpp_fd_read(rpp_stdin, &frq, sizeof frq, NULL);
		alarm(0);
		if (len != sizeof frq) {
			if (errno == EINTR)
				continue;
			grad_log(GRAD_LOG_ERR,
			         _("Child received malformed header (len = %d, error = %s)"),
			         len, strerror(errno));
			radiusd_exit0();
		}

		if (datasize < frq.size) {
			datasize = frq.size;
			data = grad_erealloc(data, datasize);
		}
		
		if (rpp_fd_read(rpp_stdin, data, frq.size, NULL) != frq.size) {
			grad_log(GRAD_LOG_ERR,
			         _("Child received malformed data"));
			radiusd_exit0();
		}

		req = request_create(frq.type, frq.fd,
				     &frq.srv_addr, &frq.clt_addr,
				     data, frq.size);

		req->status = RS_COMPLETED;
		rc = request_handle(req, request_respond);
			
		/* Inform the master */
		GRAD_DEBUG(1, "notifying the master");
		repl.code = RPP_COMPLETE;
		repl.size = 0;
		rpp_fd_write(rpp_stdout, &repl, sizeof repl, NULL);
		if (rc)
			request_free(req);
	}
	return 0;
}

/* Master: Read notification from the child and update the request queue */
int
rpp_input_handler(int fd, void *data)
{
	struct rpp_reply repl;
	rpp_proc_t *p = rpp_lookup_fd(fd);
	struct timeval tv, *tvp;
	int sz;

	grad_insist(p != NULL);
	
	if (radiusd_read_timeout) {
		tv.tv_sec = radiusd_read_timeout;
		tv.tv_usec = 0;
		tvp = &tv;
	} else
		tvp = NULL;

	sz = rpp_fd_read(fd, &repl, sizeof(repl), tvp);
	if (sz == sizeof(repl)) {
		void *data = NULL;

		if (repl.size) {
			data = grad_emalloc(repl.size);
			if (rpp_fd_read(fd, data, repl.size, tvp)
			    != repl.size) {
				_rpp_slay(p, _("error reading data"));
				grad_free(data);
				return 1;
			}
		}
		
		if (p) {
		        GRAD_DEBUG1(1, "updating pid %d", p->pid);
			p->status = process_ready;
			request_update(p->pid, RS_COMPLETED, data);
		} 
		grad_free(data);
	} else if (sz != 0) {
		_rpp_slay(p, _("error reading data; wrong data size returned"));
		return 1;
	}
	
	return 0;
}

/* Client: Send an update to the master */
int
rpp_update(void *data, size_t size)
{
	struct rpp_reply repl;

	repl.code = RPP_UPDATE;
	repl.size = size;
	rpp_fd_write(rpp_stdout, &repl, sizeof repl, NULL);
	rpp_fd_write(rpp_stdout, data, size, NULL);
	return 0;
}

int
rpp_input_close(int fd, void *data)
{
	rpp_proc_t *p = rpp_lookup_fd(fd);
	if (p)
		_rpp_remove(p);
	return 0;
}



/* Don't use it. It's a debugging hook */
int
wd()
{
	int volatile _st=0;
	while (!_st)
		_st=_st;
}
