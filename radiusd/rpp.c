/* This file is part of GNU Radius.
   Copyright (C) 2003 Sergey Poznyakoff
  
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

/* RPP is a Radius Process Pool */

#define RADIUS_MODULE_RPP_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <radiusd.h>
#include <list.h>

/* Process intercommunication primitives */

typedef struct {
	pid_t pid;   
	int p[2];
	int ready;
} rpp_proc_t;

static int
pipe_write(int fd, void *ptr, size_t size, struct timeval *tv)
{
	if (!tv)
		return write(fd, ptr, size);
	else {
		char *data = ptr;
		int rc;
		struct timeval to;
		fd_set wr_set;
		size_t n;
		
		for (n = 0; n < size;) {
			to = *tv;
			FD_ZERO(&wr_set);
			FD_SET(fd, &wr_set);
			rc = select(fd + 1, NULL, &wr_set, NULL, &to);
			if (rc == 0)
				break;
			else if (rc < 0) {
				if (errno == EINTR)
					continue;
				break;
			} else if (rc > 0) {
				rc = write(fd, data, 1);
				if (rc != 1) 
					break;
				data++;
				n++;
			}
		}
		return n;
	}
}

static int
pipe_read(int fd, void *ptr, size_t size, struct timeval *tv)
{
	int rc;

	if (!tv) {
		int rdbytes = 0;
		do {
			rc = read(fd, ptr, size);
			if (rc > 0) {
				ptr += rc;
				size -= rc;
				rdbytes += rc;
			} else
				break;
		} while (size > 0);
		return rdbytes;
	} else {
		char *data = ptr;
		struct timeval to;
		fd_set rd_set;
		size_t n;
		
		for (n = 0; n < size;) {
			to = *tv;
			FD_ZERO(&rd_set);
			FD_SET(fd, &rd_set);
			rc = select(fd + 1, &rd_set, NULL, NULL, &to);
			if (rc == 0)
				break;
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

static int
rpp_fd_read(int fd, void *data, size_t size, struct timeval *tv)
{
	size_t sz, nbytes;

	sz = pipe_read(fd, &nbytes, sizeof(nbytes), tv);
	if (sz == 0)
		return 0; /* eof */
	if (sz != sizeof(nbytes)) 
		return -1;
	sz = nbytes > size ? size : nbytes;
	if (pipe_read (fd, data, sz, tv) != sz)
		return -2;
	for (;nbytes > size; nbytes--) {
		char c;
		pipe_read(fd, &c, 1, tv);
	}
	
	return sz;
}

static int
rpp_fd_write(int fd, void *data, size_t size, struct timeval *tv)
{
	if (pipe_write(fd, &size, sizeof(size), tv) != sizeof(size))
		return -1;
	if (pipe_write(fd, data, size, tv) != size)
		return -2;
	return size;
}

int
rpp_start_process(rpp_proc_t *proc, int (*proc_main)(void *), void *data)
{
	int inp[2];
	int outp[2];
	pid_t pid;
	
	if (pipe(inp)) {
		radlog(L_ERR, "pipe(inp): %s", strerror(errno));
		return -1;
	}
	
	if (pipe(outp)) {
		radlog (L_ERR, "pipe(outp): %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		radlog (L_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* Child */

		/* Close remote side of pipes */
		close(inp[0]);
		close(outp[1]);
		/* Close stdio */
		close(0);
		close(1);
		
		/* Duplicate i/o channels to stdio */
		dup(outp[0]);  /* This becomes standard in */
		dup(inp[1]);   /* and this standard out */

		/* Run the main process */
		exit(proc_main(data));
	}

	/* Parent */
	close (inp[1]);
	close (outp[0]);

	proc->pid = pid;
	proc->p[0] = inp[0];
	proc->p[1] = outp[1];
	proc->ready = 1;
	return 0;
}

  

static RAD_LIST *process_list; /* List of rpp_proc_t */

rpp_proc_t *
rpp_lookup_fd(int fd)
{
	rpp_proc_t *p;
	ITERATOR *itr = iterator_create(process_list);
	for (p = iterator_first(itr); p; p = iterator_next(itr))
		if (p->p[0] == fd)
			break;
	iterator_destroy(&itr);
	return p;
}

rpp_proc_t *
rpp_lookup_ready(int (*proc_main)(void *), void *data)
{
	rpp_proc_t *p;

	if (process_list) {
		ITERATOR *itr = iterator_create(process_list);
		for (p = iterator_first(itr); p && !p->ready;
		     p = iterator_next(itr))
			;
		iterator_destroy(&itr);
	} else {
		process_list = list_create();
		p = NULL;
	}
	
	if (!p) {
		rpp_proc_t proc;
		if (list_count(process_list) == max_children) 
			return NULL;
		if (rpp_start_process(&proc, proc_main, data)) 
			return NULL;
		radiusd_register_input_fd("rpp", proc.p[0], NULL);
		p = emalloc(sizeof(*p));
		*p = proc;
		list_append(process_list, p);
	}
	return p;
}

rpp_proc_t *
rpp_lookup_pid(pid_t pid)
{
	rpp_proc_t *p;
	ITERATOR *itr = iterator_create(process_list);
	for (p = iterator_first(itr); p; p = iterator_next(itr)) {
		if (p->pid == pid)
			break;
	}
	iterator_destroy(&itr);
	return p;
}
	
static void
_rpp_remove(rpp_proc_t *p)
{
	close(p->p[0]);
	close(p->p[1]);
	radiusd_close_channel(p->p[0]);
	if (list_remove(process_list, p, NULL))
		efree(p);
}

void
rpp_remove(pid_t pid)
{
	rpp_proc_t *p = rpp_lookup_pid(pid);
	if (p)
		_rpp_remove(p);
}


static int rpp_request_handler(void *arg);

int
rpp_ready(pid_t pid)
{
	if (pid == 0) {  
		if (rpp_lookup_ready(rpp_request_handler, NULL))
			return 1;
	} else {
		rpp_proc_t *p;
		ITERATOR *itr = iterator_create(process_list);

		for (p = iterator_first(itr); p; p = iterator_next(itr)) {
			if (p->pid == pid) {
				break;
			}
		}
	        iterator_destroy(&itr);
		if (p && p->ready)
			return 1;
	}
	return 0;
}

void
rpp_flush(int (*fun)(void*), void *closure)
{
	time_t t;
	unsigned count;
	ITERATOR *itr = iterator_create(process_list);

	time(&t);

	do {
		rpp_proc_t *p;
		for (count = 0, p = iterator_first(itr);
		     p;
		     p = iterator_next(itr))
			if (!p->ready)
				count++;
	} while (count > 0 && (*fun)(closure) == 0);
	iterator_destroy(&itr);
}

static int
_kill_itr(void *item, void *data)
{
	rpp_proc_t *p = item;
	kill(p->pid, *(int*)data);
	return 0;
}
	
int
rpp_kill(pid_t pid, int signo)
{
	if (pid > 0) {
		rpp_proc_t *p = rpp_lookup_pid(pid);
		if (p) {
			kill(p->pid, signo);
			_rpp_remove(p);
		} else
     		        return 1;
	} else 
		list_iterate(process_list, _kill_itr, &signo);
	return 0;
}

static void
_rpp_slay(rpp_proc_t *p)
{
	radlog(L_NOTICE, _("Killing unresponding process %lu"), (u_long) p->pid);
	kill(p->pid, SIGKILL);
	_rpp_remove(p);
}

size_t
rpp_count()
{
	return list_count(process_list);
}

struct rpp_request {
	int type;                  /* Request type */
	struct sockaddr_in addr;   /* Sender address */
	int fd;                    /* Source descriptor */
	size_t size;               /* Size of the raw data */
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
	debug(1, ("sending request to %d", p->pid));
	
	frq.type = req->type;
	frq.addr = req->addr;
	frq.fd = req->fd;
	frq.size = req->rawsize;
	
	p->ready = 0;
	req->child_id = p->pid;

	if (radiusd_write_timeout) {
		tv.tv_sec = radiusd_write_timeout;
		tv.tv_usec = 0;
		tvp = &tv;
	} else
		tvp = NULL;
	
 	if (rpp_fd_write(p->p[1], &frq, sizeof frq, tvp) != sizeof frq
	    || rpp_fd_write(p->p[1], req->rawdata, req->rawsize, tvp) != req->rawsize) {
		_rpp_slay(p);
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
		radlog(L_INFO, _("Child exiting on timeout."));
		/*FALLTHRU*/
		
	case SIGTERM:
	case SIGQUIT:
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
	signal(sig, sig_handler);
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
	signal(SIGALRM, sig_handler);
	request_init_queue();
#ifdef USE_SERVER_GUILE
        scheme_redirect_output();
#endif
	
	while (1) {
		int rc;
		int len;

		alarm(process_timeout);
		len = rpp_fd_read(0, &frq, sizeof frq, NULL);
		alarm(0);
		if (len != sizeof frq) {
			radlog(L_ERR,
			       _("Child received malformed header (len = %d, error = %s)"),
			       len, strerror(errno));
			radiusd_exit0();
		}

		if (datasize < frq.size) {
			datasize = frq.size;
			data = erealloc(data, datasize);
		}
		
		if (rpp_fd_read(0, data, frq.size, NULL) != frq.size) {
			radlog(L_ERR,
			       _("Child received malformed data"));
			radiusd_exit0();
		}
		
		req = request_create(frq.type, frq.fd, &frq.addr,
				     data, frq.size);
		req->status = RS_COMPLETED;
		rc = request_handle(req, request_respond);
			
		/* Inform the master */
		debug(1, ("notifying the master"));
		repl.code = RPP_COMPLETE;
		repl.size = 0;
		rpp_fd_write(1, &repl, sizeof repl, NULL);
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
	
	insist(p != NULL);
	
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
			data = emalloc(repl.size);
			if (rpp_fd_read(fd, data, repl.size, tvp)
			    != repl.size) {
				_rpp_slay(p);
				efree(data);
				return 1;
			}
		}
		
		if (p) {
		        debug(1, ("updating pid %d", p->pid));
			p->ready = 1;
			request_update(p->pid, RS_COMPLETED, data);
		} 
		efree(data);
	} else if (sz != 0) {
		_rpp_slay(p);
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
	rpp_fd_write(1, &repl, sizeof repl, NULL);
	rpp_fd_write(1, data, size, NULL);
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


int
wd()
{
	int volatile _st=0;
	while (!_st)
		_st=_st;
}
