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

#define request_list_block() \
 pthread_mutex_lock(&request_list_mutex);
#define request_list_unblock() \
 pthread_mutex_unlock(&request_list_mutex)
        
static void request_free(REQUEST *req);
static void request_drop(int type, void *data, char *status_str);
static void request_xmit(int type, int code, void *data, int fd);
static void request_cleanup(int type, void *data);
static void *request_thread0(void *arg);

static pthread_mutex_t request_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t request_cond = PTHREAD_COND_INITIALIZER;

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

void *
request_thread0(arg)
	void *arg;
{
        sigset_t sig;
        
        sigemptyset(&sig);
        pthread_sigmask(SIG_SETMASK, &sig, NULL);

        while (1) {
		REQUEST *req;
		while (req = request_get())
			request_handle(req);
		pthread_mutex_lock(&request_mutex);
		debug(1,("thread waiting"));
                pthread_cond_wait(&request_cond, &request_mutex);
		pthread_mutex_unlock(&request_mutex);
	}
	/*NOTREACHED*/
	return NULL;
}

void
request_signal()
{
	debug(1,("signalling"));
	pthread_cond_signal(&request_cond);
}

void
request_free(req)
        REQUEST *req;
{
        request_class[req->type].free(req->data);
        free_entry(req);
}

void
request_drop(type, data, status_str)
        int type;
        void *data;
        char *status_str;
{
        request_class[type].drop(type, data, status_str);
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
        else 
                request_class[type].drop(type, data, _("duplicate request"));

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
		if (curreq->status == RS_WAITING) {
			curreq = curreq->next;
			continue;
		}

		if (curreq->status == RS_PENDING)
			++*numpending;

		if (curreq->status == RS_COMPLETED
		    && curreq->timestamp + 
		    request_class[curreq->type].cleanup_delay <= curtime) {
                        /*
                         *      Request completed, delete it
                         */
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
                }
 
                if (curreq->type == type
                    && request_cmp(type, curreq->data, data) == 0) {
                        /* This is a duplicate request.
                           If the handling process has already finished --
                           retransmit it's results, if possible.
                           Otherwise just drop the request. */
                        if (curreq->status == RS_COMPLETED) 
                                request_xmit(type, curreq->child_return, data,
                                             activefd);
                        else
                                request_drop(type, data,
                                             _("duplicate request"));
                        request_list_unblock();

                        return NULL;
                } else {
                        if (curreq->timestamp +
                            request_class[curreq->type].ttl <= curtime
                            && curreq->status == RS_PENDING) {
                                /* This request seems to have hung */
                                radlog(L_NOTICE,
                                     _("Killing unresponsive %s child pid %d"),
                                       request_class[curreq->type].name,
                                       curreq->child_id);
                                pthread_cancel(curreq->child_id);
				num_threads--;
                                curreq = curreq->next;
                                continue;
                        }
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
        if (request_count >= config.max_requests) {
                if (!to_replace) {
                        request_drop(type, data,
                                     _("too many requests in queue"));

                        request_list_unblock();
                        return NULL;
                }
        } else if (request_class[type].max_requests
                   && request_type_count >= request_class[type].max_requests) {
                if (!to_replace) {
                        request_drop(type, data,
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
		if (curreq->status == RS_WAITING)
			break;
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
                if (curreq->child_id == RS_COMPLETED) {
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
                               _("Killing unresponsive %s child pid %d"),
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
        int     pending_count[R_MAX] = {0};
        int     completed_count[R_MAX] = {0};
        REQUEST *curreq;
        int     i;
        
        curreq = first_request;
        /* Block asynchronous access to the list
         */
        request_list_block();

        while (curreq != NULL) {
                if (curreq->child_id == RS_COMPLETED) 
                        completed_count[curreq->type]++;
                else
                        pending_count[curreq->type]++;

                curreq = curreq->next;
        }
        request_list_unblock();

        /* Report the results */
        for (i = 0; request_class[i].name; i++) {
                stat[i][0] = pending_count[i];
                stat[i][1] = completed_count[i];
        }

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
        debug(2, ("cleaning up request %lu", curreq->child_id));
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

	debug(1, ("called"));
        pthread_cleanup_push(rad_cleanup_thread, req);
	req->status = RS_PENDING;
	time(&req->timestamp);
	debug(1, ("setup: %p", request_class[req->type].setup) );
	if (request_class[req->type].setup) 
		rc = request_class[req->type].setup(req);
	if (rc == 0)
		req->child_return = request_class[req->type].handler(req->data,
								     req->fd);
        pthread_cleanup_pop(1);
        log_close();
	debug(1, ("exiting"));
}
