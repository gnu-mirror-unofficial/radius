/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_REQUEST_C

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radiusd.h>

extern struct request_class request_class[];

/* the request queue */
static REQUEST *first_request;
pthread_mutex_t request_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#define request_list_block()   Pthread_mutex_lock(&request_list_mutex)
#define request_list_unblock() Pthread_mutex_unlock(&request_list_mutex)
        
static void request_free(REQUEST *req);
static void request_drop(int type, void *data, void *orig_data, int fd,
			 char *status_str);
static void request_xmit(int type, int code, void *data, int fd);
static void request_cleanup(int type, void *data);
static void *request_thread0(void *arg);
static int request_process_command();

static pthread_mutex_t request_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t request_cond = PTHREAD_COND_INITIALIZER;

static request_thread_command_fp request_command;
static void *request_command_arg;
static int request_command_count;

int
request_start_thread()
{
        pthread_t tid;
        int rc = pthread_create(&tid, &thread_attr, request_thread0, NULL);
        if (rc) {
                radlog(L_ERR, _("Can't spawn new thread: %s"),
                       strerror(rc));
                return -1;
        }
        num_threads++;
        debug(1, ("started new thread: %x", (u_long) tid));
        return 0;
}

void
rad_cleanup_thread0(arg)
        void *arg;
{
	num_threads--;
}

void *
request_thread0(arg)
        void *arg;
{
	rad_thread_init();

	pthread_cleanup_push(rad_cleanup_thread0, NULL);
        while (1) {
                REQUEST *req;

		request_process_command();
		
                while (req = request_get())
                        request_handle(req);
                Pthread_mutex_lock(&request_mutex);
                debug(1,("thread waiting"));
                pthread_cond_wait(&request_cond, &request_mutex);
                debug(1,("thread waken up"));
                Pthread_mutex_unlock(&request_mutex);
        }
        /*NOTREACHED*/
	pthread_cleanup_pop(1);
        return NULL;
}

void
request_signal()
{
        Pthread_mutex_lock(&request_mutex);
        debug(100,("Signalling"));
        pthread_cond_signal(&request_cond);
        Pthread_mutex_unlock(&request_mutex);
}

int
request_process_command()
{
	if (request_command) {
		(*request_command)(request_command_arg);
		request_command_count++;
		return 1;
	}
	return 0;
}

void
request_thread_command(fun, data)
	request_thread_command_fp fun;
	void *data;
{
        Pthread_mutex_lock(&request_mutex);
	request_command = fun;
	request_command_arg = data;
	request_command_count = 0;
        debug(100,("Signalling"));
        pthread_cond_broadcast(&request_cond);
        Pthread_mutex_unlock(&request_mutex);
	while (request_command_count < num_threads)
		;
	request_command = NULL;
}

void
request_free(req)
        REQUEST *req;
{
        request_class[req->type].free(req->data);
        free_entry(req);
}

void
request_drop(type, data, orig_data, fd, status_str)
        int type;
        void *data;
	void *orig_data;
	int fd;
        char *status_str;
{
        request_class[type].drop(type, data, orig_data, fd, status_str);
}

void
request_xmit(type, code, data, fd)
        int type;
        int code;
        void *data;
        int fd;
{
        if (request_class[type].xmit) 
                request_class[type].xmit(type, code, data, fd);

        switch (type) {
        case R_AUTH:
                stat_inc(auth, ((RADIUS_REQ*)data)->ipaddr, num_dup_req);
                break;
        case R_ACCT:
                stat_inc(acct, ((RADIUS_REQ*)data)->ipaddr, num_dup_req);
        }
}

int
request_cmp(type, a, b)
        int type;
        void *a, *b;
{
        return request_class[type].comp(a, b);
}

void
request_cleanup(type, data)
        int type;
        void *data;
{
        if (request_class[type].cleanup)
                request_class[type].cleanup(type, data);
}

REQUEST *
request_put(type, data, activefd, numpending)
        int type;
        void *data;
        int activefd;
        unsigned *numpending;
{
        REQUEST *curreq;
        REQUEST *prevreq;
        REQUEST *to_replace;
        time_t curtime;
        int request_count, request_type_count;

        time(&curtime);
        request_count = request_type_count = 0;
        curreq = first_request;
        prevreq = NULL;
        to_replace = NULL; 
        *numpending = 0;
        
        /* Block asynchronous access to the list */
        request_list_block();

        while (curreq != NULL) {

                if (curreq->status == RS_PENDING)
                        ++*numpending;

                if (curreq->status == RS_COMPLETED
                    && curreq->timestamp +
                    request_class[curreq->type].cleanup_delay <= curtime) {
                        debug(1, ("deleting completed %s request",
                                  request_class[curreq->type].name));
                        if (prevreq == NULL) {
                                first_request = curreq->next;
                                request_free(curreq);
                                curreq = first_request;
                        } else {
                                prevreq->next = curreq->next;
                                request_free(curreq);
                                curreq = prevreq->next;
                        }
                        continue;
                } else if (curreq->timestamp + 
                           request_class[curreq->type].ttl <= curtime) {
                        switch (curreq->status) {
                        case RS_WAITING:
                                request_drop(curreq->type, NULL, curreq->data,
					     curreq->fd,
                                             _("request timed out in queue"));
                                
                                if (prevreq == NULL) {
                                        first_request = curreq->next;
                                        request_free(curreq);
                                        curreq = first_request;
                                } else {
                                        prevreq->next = curreq->next;
                                        request_free(curreq);
                                        curreq = prevreq->next;
                                }
                                break;
                                
                        case RS_PENDING:
                                radlog(L_NOTICE,
                                     _("Killing unresponsive %s thread %d"),
                                       request_class[curreq->type].name,
                                       curreq->child_id);
                                /*FIXME: This causes much grief */
                                pthread_cancel(curreq->child_id);
				/* Prevent successive invocations of
				   pthread_cancel */
				curreq->timestamp = curtime;
                                curreq = curreq->next;
                                break;
                        }
                        continue;
                }
 
                if (curreq->type == type
                    && request_cmp(type, curreq->data, data) == 0) {
                        /* This is a duplicate request.
                           If the handling process has already finished --
                           retransmit its results, if possible.
                           Otherwise drop the request. */
                        if (curreq->status == RS_COMPLETED) 
                                request_xmit(type,
                                             curreq->child_return,
                                             curreq->data,
                                             activefd);
                        else
                                request_drop(type, data, curreq->data,
					     curreq->fd,
                                             _("duplicate request"));
                        request_list_unblock();

                        return NULL;
                } else {
                        if (curreq->type == type) {
                                request_type_count++;
                                if (type != R_PROXY
                                    && curreq->status == RS_COMPLETED
                                    && (to_replace == NULL
                                        || to_replace->timestamp >
                                                           curreq->timestamp))
                                        to_replace = curreq;
                        }
                        request_count++;
                        prevreq = curreq;
                        curreq = curreq->next;
                }
        }

        /* This is a new request */
        if (request_count >= max_requests) {
                if (!to_replace) {
                        request_drop(type, data, NULL,
				     activefd,
                                     _("too many requests in queue"));

                        request_list_unblock();
                        return NULL;
                }
        } else if (request_class[type].max_requests
                   && request_type_count >= request_class[type].max_requests) {
                if (!to_replace) {
                        request_drop(type, data, NULL,
				     activefd,
                                     _("too many requests of this type"));

                        request_list_unblock();
                        return NULL;
                }
        } else
                to_replace = NULL;

        /*
         * Add this request to the list
         */
        if (to_replace == NULL) {
                curreq = alloc_entry(sizeof *curreq);
                curreq->next = first_request;
                first_request = curreq;
        } else {
                debug(1, ("replacing request dated %s",
                          ctime(&to_replace->timestamp)));
                                
                request_class[to_replace->type].free(to_replace->data);
                curreq = to_replace;
        }

        curreq->timestamp = curtime;
        curreq->type = type;
        curreq->data = data;
        curreq->child_id = 0;
        curreq->status = RS_WAITING;
        curreq->fd = activefd;
        
        debug(1, ("%s request %lu added to the list. %d requests held.", 
                  request_class[type].name,
                  (u_long) curreq->child_id,
                  request_count+1));

        request_list_unblock();

        return curreq;
}

REQUEST *
request_get()
{
        REQUEST *curreq;

        request_list_block();
        for (curreq = first_request; curreq; curreq = curreq->next) 
                if (curreq->status == RS_WAITING) {
                        curreq->status = RS_PENDING;
                        curreq->child_id = pthread_self();
                        time(&curreq->timestamp);
                        break;
                }
        request_list_unblock();
        return curreq;
}

int
request_flush_list()
{
        REQUEST *curreq;
        REQUEST *prevreq;
        time_t  curtime;
        int     request_count;
        
        time(&curtime);
        request_count = 0;
        curreq = first_request;
        prevreq = NULL;

        /* Block asynchronous access to the list
         */
        request_list_block();

        while (curreq != NULL) {
                if (curreq->status == RS_COMPLETED) {
                        /* Request completed, delete it no matter how
                           long does it reside in the queue */
                        debug(1, ("deleting completed %s request",
                                 request_class[curreq->type].name));
                        if (prevreq == NULL) {
                                first_request = curreq->next;
                                request_free(curreq);
                                curreq = first_request;
                        } else {
                                prevreq->next = curreq->next;
                                request_free(curreq);
                                curreq = prevreq->next;
                        }
                } else if (curreq->timestamp +
                           request_class[curreq->type].ttl <= curtime) {
                        /* kill the request */
                        radlog(L_NOTICE,
                               _("Killing unresponsive %s thread %d"),
                               request_class[curreq->type].name,
                               curreq->child_id);
                        pthread_cancel(curreq->child_id);
                        curreq = curreq->next;
                } else {
                        prevreq = curreq;
                        curreq = curreq->next;
                        request_count++;
                }
        }

        request_list_unblock();
        return request_count;
}

int
request_stat_list(stat)
        QUEUE_STAT stat;
{
        REQUEST *curreq;

        memset(stat, 0, sizeof(QUEUE_STAT));
        
        /* Block asynchronous access to the list
         */
        request_list_block();
        for (curreq = first_request; curreq != NULL; curreq = curreq->next) {
                switch (curreq->status) {
                case RS_COMPLETED:
                        stat[curreq->type].completed++;
                        break;
                case RS_PENDING:
                        stat[curreq->type].pending++;
                        break;
                case RS_WAITING:
                        stat[curreq->type].waiting++;
                        break;
                }
        }
        request_list_unblock();

        return 0;
}

void *
request_scan_list(type, handler, closure)
        int type;
        int (*handler)();
        void *closure;
{
        REQUEST *curreq;

        for (curreq = first_request; curreq; curreq = curreq->next) {
                if (curreq->type == type &&
                    handler(closure, curreq->data) == 0)
                        return curreq->data;
        }
        return NULL;
}

void
rad_cleanup_thread(arg)
        void *arg;
{
        REQUEST *curreq = arg;
        debug(1, ("cleaning up request %lu", (u_long) curreq->child_id));
        curreq->child_id = 0;
        curreq->status = RS_COMPLETED;
        time(&curreq->timestamp);
        request_cleanup(curreq->type, curreq->data);
}

void
request_handle(req)
        REQUEST *req;
{
        int rc = 0;

        if (!req)
                return;

        pthread_cleanup_push(rad_cleanup_thread, req);
        req->status = RS_PENDING;
        req->child_id = pthread_self();
        time(&req->timestamp);
        debug(1, ("setup: %lu: %p",
                  (u_long) req->child_id, request_class[req->type].setup));
        if (request_class[req->type].setup) 
                rc = request_class[req->type].setup(req);
        if (rc == 0)
                req->child_return = request_class[req->type].handler(req->data,
                                                                     req->fd);
        pthread_cleanup_pop(1);
        log_close();
        debug(1, ("exiting"));
}

