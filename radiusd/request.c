/* This file is part of GNU Radius.
   Copyright (C) 2002,2003 Sergey Poznyakoff
  
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

#define RADIUS_MODULE_REQUEST_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <errno.h>
#include <radiusd.h>
#include <radsql.h>
#include <list.h>

struct request_class request_class[] = {
        { "AUTH", 0, MAX_REQUEST_TIME, CLEANUP_DELAY,
	  radius_req_decode,   /* Decoder */
          radius_respond,      /* Handler */
	  radius_req_xmit,     /* Retransmitter */
	  radius_req_cmp,      /* Comparator */
          radius_req_free,     /* Deallocator */
	  radius_req_drop,     /* Drop function */
	  rad_sql_cleanup,  /* Cleanup function */
	  radius_req_failure,  /* Failure indicator */
	},
        { "ACCT", 0, MAX_REQUEST_TIME, CLEANUP_DELAY,
	  radius_req_decode,   /* Decoder */
          radius_respond,      /* Handler */
	  radius_req_xmit,     /* Retransmitter */
	  radius_req_cmp,      /* Comparator */
          radius_req_free,     /* Deallocator */
	  radius_req_drop,     /* Drop function */
	  rad_sql_cleanup,  /* Cleanup function */
	  radius_req_failure,  /* Failure indicator */
	},
        { "PROXY",0, MAX_REQUEST_TIME, CLEANUP_DELAY,
	  radius_req_decode,   /* Decoder */
          rad_proxy,        /* Handler */
	  radius_req_xmit,     /* Retransmitter */
	  radius_req_cmp,      /* Comparator */ 
          radius_req_free,     /* Deallocator */  
	  proxy_retry,      /* Drop function */ 
	  NULL,             /* Cleanup function */
	  NULL,             /* Failure indicator */
	},
#ifdef USE_SNMP
        { "SNMP", 0, MAX_REQUEST_TIME, 0, 
	  snmp_decode,      /* Decoder */
	  snmp_answer,      /* Handler */
	  NULL,             /* Retransmitter */ 
	  snmp_req_cmp,     /* Comparator */ 
          snmp_req_free,    /* Deallocator */  
	  snmp_req_drop,    /* Drop function */ 
	  NULL,             /* Cleanup function */
	  NULL,             /* Failure indicator */
	},
#endif
        { NULL, }
};

static LIST *request_list; /* List of REQUEST structures */


/* ************************* General-purpose functions ********************* */

REQUEST *
request_create(int type, int fd, struct sockaddr_in *sa,
	       u_char *buf, size_t bufsize)
{
	void *data;
	REQUEST *req;

	if (request_class[type].decode(sa, buf, bufsize, &data))
		return NULL;
	req = emalloc(sizeof *req);
	req->data = data;
	time(&req->timestamp);
        req->type = type;
	req->addr = *sa;
	req->rawdata = emalloc(bufsize);
	memcpy(req->rawdata, buf, bufsize);
	req->rawsize = bufsize;
        req->child_id = 0;
        req->status = RS_WAITING;
        req->fd = fd;
	return req;
}

void
request_free(REQUEST *req)
{
	if (req) {
		request_class[req->type].free(req->data);
		efree(req->rawdata);
		efree(req);
	}
}

void
request_drop(int type, void *data, void *orig_data, int fd, char *status_str)
{
        request_class[type].drop(type, data, orig_data, fd, status_str);
}

int
request_respond(REQUEST *req)
{
	return request_class[req->type].respond(req);
}

void
request_xmit(REQUEST *req)
{
        if (request_class[req->type].xmit) 
                request_class[req->type].xmit(req);
}

int
request_cmp(int type, void *a, void *b)
{
        return request_class[type].comp(a, b);
}

void
request_cleanup(int type, void *data)
{
        if (request_class[type].cleanup)
                request_class[type].cleanup(type, data);
}

struct request_closure {
	int type;                  /* Type of the request */
	void *data;                /* Request contents */
	time_t curtime;            /* Current timestamp */
	/* Output: */
        size_t request_count;      /* Total number of requests */
	size_t request_type_count; /* Number of requests of this type */
};

static int
_request_iterator(void *item, void *data)
{
	REQUEST *req = item;
	struct request_closure *rp = data;
	
	if (req->status == RS_COMPLETED) {
		if (req->timestamp + request_class[req->type].cleanup_delay
		             <= rp->curtime) {
			debug(1, ("deleting completed %s request",
				  request_class[req->type].name));
			list_remove_current(request_list);
			request_free(req);
			return 0;
		}
	} else if (req->timestamp + request_class[req->type].ttl
		      <= rp->curtime) {

		radlog(L_NOTICE,
		       _("Killing unresponsive %s child %lu"),
		       request_class[req->type].name,
		       (unsigned long) req->child_id);
		rpp_kill(req->child_id, SIGKILL);
		rpp_remove(req->child_id);
		return 0;
	}

	if (!rp->data)
		return 0;
	
	if (req->type == rp->type
	    && request_cmp(req->type, req->data, data) == 0) {
		/* This is a duplicate request. If it is already completed,
		   then hand it over to the child.
		   Otherwise drop the request. */
		if (req->status == RS_COMPLETED) {
			if (radiusd_master())
				rpp_forward_request(req);
			else
                                request_xmit(req);

		} else
			request_drop(req->type, data, req->data, req->fd,
				     _("duplicate request"));
		/* Indicate end of request processing */
		rp->data = NULL;
		return 0;
	} else {
		if (req->type == rp->type) 
			rp->request_type_count++;
		rp->request_count++;
        }
	return 0;
}

int
request_handle(REQUEST *req, int (*handler)(REQUEST *))
{
	struct request_closure rc;

	if (!req)
		return 1;
	
	rc.type = req->type;
	rc.data = req->data;
        time(&rc.curtime);
        rc.request_count = rc.request_type_count = 0;

	if (!request_list)
		request_list = list_create();
	else
		list_iterate(request_list, _request_iterator, &rc);

	if (!rc.data)
		return 1;
	
        /* This is a new request */
        if (rc.request_count >= max_requests) {
		request_drop(req->type, req->data, NULL, req->fd,
			     _("too many requests in queue"));
		return 1;
        } else if (request_class[req->type].max_requests
                   && rc.request_type_count >= request_class[req->type].max_requests) {
		request_drop(req->type, req->data, NULL, req->fd,
			     _("too many requests of this type"));
		return 1;
        } 

	/* Do we have free handlers? */
	if (radiusd_master() && !rpp_ready()) {
		radlog(L_NOTICE, _("Maximum number of children active"));
		return 1;
	}
	
	/* Add request to the queue */
        debug(1, ("%s request %lu added to the list. %d requests held.", 
                  request_class[req->type].name,
                  (u_long) req->child_id,
                  rc.request_count+1));

	list_append(request_list, req);
	return (*handler)(req);
}

void
request_set_status(pid_t pid, int status)
{
	REQUEST *p;

	for (p = list_first(request_list); p; p = list_next(request_list))
		if (p->child_id == pid) {
			p->status = status;
			break;
		}
}
			

void
request_fail(int type, struct sockaddr_in *addr)
{
	if (request_class[type].failure)
		request_class[type].failure(type, addr);
}

static int
_destroy_request(void *item, void *data)
{
	request_free((REQUEST*)item);
	return 0;
}

void
request_init_queue()
{
	list_destroy(&request_list, _destroy_request, NULL);
}

void *
request_scan_list(int type, list_iterator_t itr, void *closure)
{
	REQUEST *p;

	for (p = list_first(request_list); p; p = list_next(request_list)) {
                if (p->type == type
		    && itr(p->data, closure) == 0)
                        return p->data;
        }
        return NULL;
}
