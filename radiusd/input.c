/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2006,2007 Free Software Foundation, Inc.

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
#include <errno.h>

#include <radiusd.h>

struct input_system {
	fd_set fdset;
	int fd_max;
	grad_list_t *methods;    /* List of METHOD structures */
	grad_list_t *channels;   /* List of CHANNEL structures */
	grad_iterator_t *citr;
};

typedef struct input_method METHOD;
struct input_method {
	const char *name;
	int prio;
	int (*handler)(int, void *);
	int (*close)(int, void *);
	int (*cmp)(const void *, const void *);
};

typedef struct input_channel CHANNEL;
struct input_channel {
	int fd;
	void *data;
	METHOD *method;
};

INPUT *
input_create()
{
	INPUT *p = grad_emalloc(sizeof(*p));
	p->methods = grad_list_create();
	p->channels = grad_list_create();
	FD_ZERO(&p->fdset);
	p->fd_max = -2;
	return p;
}

static int
def_cmp(const void *a, const void *b)
{
	return a != b;
}

void
input_register_method(INPUT *input,
		      const char *name,
		      int prio,
		      int (*handler)(int, void *),
		      int (*close)(int, void *),
		      int (*cmp)(const void *, const void *))
{
	METHOD *m = grad_emalloc(sizeof(*m));
	m->name = name;
	m->prio = prio;
	m->handler = handler;
	m->close = close;
	m->cmp = cmp ? cmp : def_cmp;
	grad_list_append(input->methods, m);
}

static int
_method_comp(const void *a, const void *b)
{
	const METHOD *ma = a;
	const char *name = b;
	return strcmp(ma->name, name);
}

int
_channel_prio_comp(const void *a, const void *b)
{
	const CHANNEL *ca = a;
	const CHANNEL *cb = b;

	return ca->method->prio - cb->method->prio;
}

int
input_register_channel(INPUT *input, char *name, int fd, void *data)
{
	CHANNEL *c;
	METHOD *m = grad_list_locate(input->methods, name, _method_comp);

	if (!m)
		return -1;
	
	c = grad_emalloc(sizeof(*c));
	c->fd = fd;
	c->data = data;
	c->method = m;
	FD_SET(fd, &input->fdset);
	if (fd > input->fd_max)
		input->fd_max = fd;
	grad_list_insert_sorted(input->channels, c, _channel_prio_comp);
	return 0;
}

static void
channel_close(INPUT *input, CHANNEL *chan)
{
	if (chan->method->close) 
		chan->method->close(chan->fd, chan->data);
	FD_CLR(chan->fd, &input->fdset);
	input->fd_max = -2;
	grad_free(chan);
}

static int
channel_handle(CHANNEL *chan)
{
	GRAD_DEBUG1(1, "handling method %s", chan->method->name);
	return chan->method->handler(chan->fd, chan->data);
}

struct _channel_cmp_closure {
	char *name;
	void *data;
};

static int
_channel_cmp(const void *a, const void *b)
{
	const CHANNEL *ca = a;
	const struct _channel_cmp_closure *clos = b;

	return strcmp(clos->name, ca->method->name)
		|| ca->method->cmp(ca->data, clos->data);
}

static int
_channel_cmp_fd(const void *a, const void *b)
{
	const CHANNEL *ca = a;
	const int *fd = b;
	return ca->fd != *fd;
}

void
input_close_channels(INPUT *input)
{
	CHANNEL *p;

	if (!input->citr)
		input->citr = grad_iterator_create(input->channels);

	for (p = grad_iterator_first(input->citr); p;
	     p = grad_iterator_next(input->citr)) {
		grad_list_remove(input->channels, p, NULL);
		channel_close(input, p);
	}
	grad_iterator_destroy(&input->citr);
}

void
input_close_channel_fd(INPUT *input, int fd)
{
	CHANNEL *p = grad_list_locate(input->channels, &fd, _channel_cmp_fd);
	
	if (p) {
		grad_list_remove(input->channels, p, NULL);
		channel_close(input, p);
	}
}

void *
input_find_channel(INPUT *input, char *name, void *data)
{
	struct _channel_cmp_closure clos;
	CHANNEL *p;

	clos.name = name;
	clos.data = data;
	p = grad_list_locate(input->channels, &clos, _channel_cmp);
	return p ? p->data : NULL;
}
		   
void
input_close_channel_data(INPUT *input, char *name, void *data)
{
	struct _channel_cmp_closure clos;
	CHANNEL *p;

	clos.name = name;
	clos.data = data;
	p = grad_list_locate(input->channels, &clos, _channel_cmp);
	if (p) {
		grad_list_remove(input->channels, p, NULL);
		channel_close(input, p);
	}
}

int
input_select(INPUT *input, struct timeval *tv)
{
	CHANNEL *p;
	int status;
	fd_set readfds;

	GRAD_DEBUG(100,"enter");
	if (!input->citr)
		input->citr = grad_iterator_create(input->channels);

	if (input->fd_max == -2) {
		for (p = grad_iterator_first(input->citr); p;
		     p = grad_iterator_next(input->citr)) {
			if (p->fd > input->fd_max)
				input->fd_max = p->fd;
		}
		if (input->fd_max == -2)
			input->fd_max = -1;
	}

	if (input->fd_max < 0) {
		pause();
		return errno;
	}
	
	readfds = input->fdset;

	status = select(input->fd_max + 1, &readfds, NULL, NULL, tv);
        
	if (status == -1) {
		if (errno == EINTR) 
			return 0;
	} else if (status > 0) {
		GRAD_DEBUG1(1, "select returned %d", status);
		
		for (p = grad_iterator_first(input->citr); p;
		     p = grad_iterator_next(input->citr)) 
			if (FD_ISSET(p->fd, &readfds)) 
				channel_handle(p);
	} 
	GRAD_DEBUG(100,"exit");
	return status;
}

int
input_select_channel(INPUT *input, char *name, struct timeval *tv)
{
	CHANNEL *p;
	int status;
	fd_set readfds;
	int fd_max = -1;
	METHOD *m = grad_list_locate(input->methods, name, _method_comp);

	GRAD_DEBUG(100,"enter");
	
	if (!m)
		return -1;
	if (!input->citr)
		input->citr = grad_iterator_create(input->channels);

	FD_ZERO(&readfds);
	for (p = grad_iterator_first(input->citr); p;
	     p = grad_iterator_next(input->citr)) {
		if (p->method == m) {
			if (p->fd > fd_max)
				fd_max = p->fd;
			FD_SET(p->fd, &readfds);
		}
	}

	if (fd_max == -1)
		return -1;
	
	status = select(fd_max + 1, &readfds, NULL, NULL, tv);
        
	if (status == -1) {
		if (errno == EINTR) 
			return 0;
	} else if (status > 0) {
		GRAD_DEBUG1(1, "select returned %d", status);
		
		for (p = grad_iterator_first(input->citr); p;
		     p = grad_iterator_next(input->citr)) 
			if (FD_ISSET(p->fd, &readfds)) 
				channel_handle(p);
	} 
	GRAD_DEBUG(100,"exit");
	return status;
}

struct iterate_closure {
	char *name;
	list_iterator_t fun;
	void *data;
};

static int
_chan_itr(void *item, void *data)
{
	CHANNEL *chan = item;
	struct iterate_closure *cp = data;
	int rc = 0;
	
	if (cp->name == NULL || strcmp(chan->method->name, cp->name) == 0)
		rc = cp->fun(chan->data, cp->data);
	return rc;
}

void
input_iterate_channels(INPUT *input, char *name,
		       list_iterator_t fun, void *data)
{
	struct iterate_closure clos;

	clos.name = name;
	clos.fun  = fun;
	clos.data = data;
	grad_list_iterate(input->channels, _chan_itr, &clos);
}
