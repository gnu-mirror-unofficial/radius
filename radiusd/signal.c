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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <signal.h>
#include <errno.h>
#include <radiusd.h>

#ifndef NSIG
# define NSIG 32
#endif

struct _signal_queue {
	struct _signal_queue *next;
	int type;
	rad_signal_t handler;
	void *data;
};

struct _signal_entry {
	int used;
	unsigned count;
	struct _signal_queue *head;
	pthread_mutex_t mutex;
};

static struct _signal_entry sigtab[NSIG];

static pthread_t signal_tid;
static pthread_mutex_t signal_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t signal_cond = PTHREAD_COND_INITIALIZER;

struct _signal_queue *
_signal_queue_install (phead, type, handler, data)
	struct _signal_queue **phead;
	int type;
	rad_signal_t handler;
	void *data;
{
	struct _signal_queue *newq = emalloc (sizeof *newq);
	newq->next = *phead;
	newq->type = type;
	newq->handler = handler;
	newq->data = data;
	*phead = newq;
	return newq;
}

int
_signal_queue_remove (phead, item)
	struct _signal_queue **phead;
	struct _signal_queue *item;
{
	struct _signal_queue *prev = NULL, *q;

	for (q = *phead; q; prev = q, q = q->next) 
		if (q == item)
			break;
	if (!q)
		return 1;
	if (q == *phead)
		*phead = q->next;
	else
		prev->next = q->next;
	efree (q);
	return 0;
}

void
_signal_entry_init (e)
	struct _signal_entry *e;
{
	pthread_mutex_init (&e->mutex, NULL);
}

void
_signal_entry_lock (e, owner)
	struct _signal_entry *e;
	const void *owner;
{
	if (e != owner)
		pthread_mutex_lock (&e->mutex);
}

void
_signal_entry_unlock (e, owner)
	struct _signal_entry *e;
	const void *owner;
{
	if (e != owner)
		pthread_mutex_unlock (&e->mutex);
}

int
_signal_entry_runqueue (sig, type, e)
	int sig;
	int type;
	struct _signal_entry *e;
{
	int rc = 1;
	struct _signal_queue *q;
	
	if (!e)
		return;
	_signal_entry_lock (e, NULL);
	
	for (q = e->head; q; ) {
		struct _signal_queue *next = q->next;
		if (q->type == type) {
			rc = q->handler (sig, q->data, (rad_sigid_t) q, e);
			if (rc == 0)
				break;
		}
		q = next;
	}
	
	_signal_entry_unlock (e, NULL);
	return rc;
}

static void
_signal_deliver (sig, type)
	int sig;
	int type;
{
	unsigned i, pass;

	if (!sigtab[sig].used || !sigtab[sig].count)
		return;
		
	for (i = pass = 0; i < sigtab[sig].count; i++)
		if (_signal_entry_runqueue (sig, type, &sigtab[sig]) == 0)
			pass++;
	sigtab[sig].count -= pass;
}

void
_awake_signal_thread ()
{
	pthread_mutex_lock (&signal_mutex);
	pthread_cond_signal (&signal_cond);
	pthread_mutex_unlock (&signal_mutex);
}

void
rad_signal_deliver ()
{
	int sig;

	for (sig = 0; sig < NSIG; sig++)
		if (sigtab[sig].used && sigtab[sig].count) {
			_awake_signal_thread ();
			break;
		}
}


void *
signal_thread0 (arg)
	void *arg;
{
	while (1) {
		int sig;
		struct timespec atime;
		struct timeval now;
		
		pthread_mutex_lock (&signal_mutex);
		gettimeofday(&now, NULL);
		atime.tv_sec = now.tv_sec;
		atime.tv_nsec = now.tv_usec * 1000 + 10;
		
		pthread_cond_wait (&signal_cond, &signal_mutex);//, &atime);
		for (sig = 0; sig < NSIG; sig++)
			_signal_deliver (sig, SH_ASYNC);
		pthread_mutex_unlock (&signal_mutex);
	}
}

int
_signal_start_thread ()
{
        int rc = pthread_create (&signal_tid,
				 &thread_attr, signal_thread0, NULL);
        if (rc) {
                radlog(L_ERR, _("Can't spawn new thread: %s"),
                       strerror(rc));
                return -1;
        }
	return 0;
}

RETSIGTYPE
signal_handler (sig)
	int sig;
{
	if (sigtab[sig].head) {
		sigtab[sig].count++;
		_signal_deliver (sig, SH_SYNC);
	}
}

rad_sigid_t
rad_signal_install (sig, type, handler, data)
	int sig;
	int type;
	rad_signal_t handler;
	void *data;
{
	struct _signal_entry *entry;
	rad_sigid_t id;
	
	if (sig < 0 || sig > NSIG) {
		errno = ENOENT;
		return 0;
	}

	if (!signal_tid)
		_signal_start_thread ();
	
	entry = &sigtab[sig];
	if (!entry->used) {
		struct sigaction act;
		
		sigtab[sig].used = 1;

		act.sa_handler = signal_handler;
		sigemptyset (&act.sa_mask);
		act.sa_flags = SA_RESTART;
		sigaction (sig, &act, NULL);
		_signal_entry_init (entry);
	}

	if (!handler)
		return NULL;
	
	_signal_entry_lock (entry, NULL);
	id = (rad_sigid_t) _signal_queue_install (&entry->head, type,
						  handler, data);
	_signal_entry_unlock (entry, NULL);
	return id;
}

rad_sigid_t
rad_signal_remove (sig, id, owner)
	int sig;
	rad_sigid_t id;
	const void *owner;
{
	struct _signal_entry *entry;

	if (sig < 0 || sig > NSIG || !sigtab[sig].used) {
		errno = ENOENT;
		return 0;
	}

	entry = &sigtab[sig];

	if (!entry->used)
		return 0;
	_signal_entry_lock (entry, owner);
	if (_signal_queue_remove (&entry->head, (struct _signal_queue*) id))
		id = NULL;
	_signal_entry_unlock (entry, owner);
	return id;
}

int
rad_signal_cleanup(sig)
	int sig;
{
	if (sigtab[sig].count)
		sigtab[sig].count--;
}
	
