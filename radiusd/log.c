/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
/*  log.c	Logging module. */

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <varargs.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sysdep.h>
#include <radiusd.h>

struct category {
	char *descr;
	struct channel *channel;
};

extern char	*radlog_dir;

char default_log[MAX_PATH_LENGTH];
int log_mode = RLOG_DEFAULT;

struct channel *chan_first, *chan_last;
struct channel default_channel;

struct category category[] = {
	NULL,          NULL,
        N_("Debug"),   NULL, 
	N_("Info"),    NULL, 
	N_("Notice"),  NULL, 
	N_("Warning"), NULL, 
	N_("Error"),   NULL, 
	N_("Crit"),    &default_channel,
	N_("Auth"),    NULL,
	N_("Proxy"),   NULL,
};

int log_to_file(char *file, int opt, char *descr, char *msg);

void
log_init()
{
	Channel *cp;

	log_cleanup(1);
	if (chan_first || chan_last) {
		radlog(L_CRIT, _("log_cleanup failed"));
		abort();
	}
			
	if (strlen(radlog_dir)+1+sizeof(RADIUS_LOG) >= sizeof(default_log)) {
		radlog(L_CRIT, _("radlog_dir too long, using default instead"));
		radlog_dir = RADLOG_DIR;
	}
	sprintf(default_log, "%s/%s", radlog_dir, RADIUS_LOG);
	
	default_channel.mode = LM_FILE;
	default_channel.options = LO_CONS|LO_PID|LO_LEVEL;
	default_channel.id.file = default_log;
	
	install_channel("null", LM_OFF, 0, NULL, 0);
	cp = install_channel("default",	LM_FILE, 0, RADIUS_LOG, LO_LEVEL);
	register_category(-1, cp);
}

void
log_cleanup(all)
	int all;
{
	Channel *cp, *next, *prev;

	prev = NULL;
	cp = chan_first;
	while (cp) {
		next = cp->next;
		if (all || cp->ucnt == 0) {
			efree(cp->name);
			if (cp->mode == LM_FILE)
				efree(cp->id.file);

			if (prev)
				prev->next = next;
			else
				chan_first = next;
			if (cp == chan_last) 
				chan_last = prev;

			efree(cp);
		} else
			prev = cp;
		cp = next;
	}
}

Channel *
channel_lookup(name)
	char *name;
{
	Channel *cp;

	for (cp = chan_first; cp; cp = cp->next)
		if (strcmp(cp->name, name) == 0)
			return cp;
	return NULL;
}

void
register_category(level, channel)
	int level;
	Channel *channel;
{
	if (channel == NULL)
		channel = channel_lookup("default");
	else if (channel->mode == LM_OFF)
		channel = NULL;
	
	if (level <= 0) {
		for (level = 1; level < NITEMS(category); level++) {
			if (level == L_CRIT)
				continue;
			category[level].channel = channel;
			if (channel)
				channel->ucnt++;
		}
	} else {
		category[level].channel = channel;
		if (channel)
			channel->ucnt++;
	}
}

Channel *
register_channel(chan)
	Channel *chan;
{
	int len;
	FILE *fp;
	Channel *channel;
	char *filename;
	
	if (chan->mode == LM_FILE) {
		len = strlen(chan->id.file) + strlen(radlog_dir) + 2;
			
		filename = emalloc(len);
		sprintf(filename, "%s/%s", radlog_dir, chan->id.file);
		
		/* check the accessibility of the file */
		fp = fopen(filename, "a");
		if (!fp) {
			radlog(L_CRIT|L_PERROR, _("can't access `%s'"), filename);
			return NULL;
		}
		fclose(fp);

	} else if (chan->mode == LM_SYSLOG) {
	} 

	channel = emalloc(sizeof(*channel));
	channel->name = estrdup(chan->name);
	channel->ucnt = 0;
	channel->mode = chan->mode;
	if (chan->mode == LM_FILE)
		channel->id.file = filename;
	else if (chan->mode == LM_SYSLOG)
		channel->id.prio = chan->id.prio;
	channel->options = chan->options;
	if (!chan_first)
		chan_first = channel;
	else
		chan_last->next = channel;
	chan_last = channel;
	return channel;
}	

Channel *
install_channel(name, mode, prio, file, options)
	char *name;
	int mode;
	int prio;
	char *file;
	int options;
{
	Channel chan;

	chan.name = name;
	chan.mode = mode;
	if (mode = LM_FILE)
		chan.id.file = file;
	else
		chan.id.prio = prio;
	chan.options = options;
	return register_channel(&chan);
}

int vlog(int lvl, char *fmt, va_list ap);

int
vlog(lvl, fmt, ap)
	int lvl;
	char *fmt;
	va_list ap;
{
	char *p, *q;
	char buffer[512];
	char msgbuf[1024];
	int prio;
	char *errstr;
	Channel *channel;
	int syserr;
		
	syserr = lvl & L_PERROR;
	lvl &= L_MASK;
	
	channel = category[lvl].channel;
	if (!channel) 
		return 0;

	errstr = strerror(errno);

#ifdef HAVE_VSNPRINTF
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
#else
# warning "Using vsprintf which does no checks for buffer overflow"	
	vsprintf(buffer, fmt, ap);
#endif	
	p = buffer;
	q = msgbuf;
	while (*p) {
		if (!isprint(*p)) {
			if (q + 4 >= msgbuf + sizeof(msgbuf))
				break;
			sprintf(q, "\\%03o", *p);
			q += 4;
			p++;
		} else
			*q++ = *p++;
	}
	*q = 0;

	/* Append system error message if necessary */
	if (syserr) {
		if (q - msgbuf + strlen(errstr) + 2 + 1 < sizeof(msgbuf)) {
			*q++ = ':';
			*q++ = ' ';
			strcpy(q, errstr);
		}
	}	

	if (channel->options & LO_CONS) {
		log_to_file("/dev/console",
			    channel->options,
			    category[lvl].descr,
			    msgbuf);
	}
	
	switch (channel->mode) {

	case LM_FILE:
		log_to_file(channel->id.file,
			    channel->options,
			    category[lvl].descr,
			    msgbuf);
		break;

	case LM_SYSLOG:
		prio = channel->id.prio;
		if (channel->options & LO_PID)
			prio |= LOG_PID;
		if (channel->options & LO_LEVEL) 
			syslog(prio, "%s: %s", _(category[lvl].descr), msgbuf);
		else
			syslog(prio, "%s", msgbuf);
	}
	
	return 0;
}

int
log_to_file(file, opt, descr, msg)
	char *file;
	int opt;
	char *descr;
	char *msg;
{
	FILE *fp;
	char buffer[256];
	time_t	timeval;
	struct tm *tm;
	
	if (strcmp(file, "stdout") != 0) {
		if (!(fp = fopen(file, "a"))) {
			fp = stdout;
		}
	} else {
		fp = stdout;
	}
		
	timeval = time(0);
	tm = localtime(&timeval);
	strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", tm);
	fprintf(fp, "%s: ", buffer);

	if (opt & LO_LEVEL) 
		fprintf(fp, "%s: ", _(descr));
		
	if (opt & LO_PID) 
		fprintf(fp, "[%lu]: ", getpid());
	
	fprintf(fp, "%s\n", msg);
	if (fp != stdout) 
		fclose(fp);
	return 0;
}

/*PRINTFLIKE2*/
int
radlog(lvl, msg, va_alist)
	int lvl;
	char *msg;
	va_dcl
{
	va_list ap;
	int r;

	va_start(ap);
	r = vlog(lvl, msg, ap);
	va_end(ap);

	return r;
}

void
debug_pair(prefix, pair)
	char *prefix;
	VALUE_PAIR *pair;
{
	Channel *channel;
	
	channel = category[L_DBG].channel;
	if (!channel)
		return;
	fprintf(stdout, "%10.10s: ", prefix);
	fprint_attr_val(stdout, pair);
	fprintf(stdout, "\n");
}


#if RADIUS_DEBUG
#include <obstack1.h>

static int debug_stack_inited;
static struct obstack debug_stack;

static void debug_init_string();
static void debug_add_string(char *str, int  len);
static void debug_add_char(int c);
static void debug_ws();
static char *debug_finish_string();

void
debug_init_string()
{
	if (debug_stack_inited) 
		obstack_free(&debug_stack, NULL);
	else
		debug_stack_inited++;
	obstack_init(&debug_stack);
}

void
debug_add_string(str, len)
	char *str;
	int  len;
{
	obstack_grow(&debug_stack, str, len);
}

void
debug_add_char(c)
	int c;
{
	obstack_1grow(&debug_stack, c);
}

void
debug_ws()
{
	debug_add_char(' ');
}

char *
debug_finish_string()
{
	debug_add_char(0);
	return obstack_finish(&debug_stack);
}

char *
debug_print_pair(pair)
	VALUE_PAIR *pair;
{
	DICT_VALUE	*dval;
	char		buffer[32];
	u_char		*ptr;
	UINT4		vendor;
	int		i, left;

	if (!pair->name)
		return "(no username)";

	insist(pair->operator >= 0 && pair->operator < PW_NUM_OPERATORS);

	debug_init_string();

	debug_add_string(pair->name, strlen(pair->name));
	debug_add_string(opstr[pair->operator], strlen(opstr[pair->operator]));

	switch (pair->type) {

	case PW_TYPE_STRING:
		debug_add_char('"');
		if (pair->attribute != DA_VENDOR_SPECIFIC) {
			debug_add_string(pair->strvalue, pair->strlength);
		} else {
			/*
			 *	Special format, print out as much
			 *	info as we can.
			 */
			ptr = (u_char *)pair->strvalue;
			if (pair->strlength < 6) {
				sprintf(buffer, "(invalid length: %d)",
					pair->strlength);
				debug_add_string(buffer, strlen(buffer));
				break;
			}
			memcpy(&vendor, ptr, 4);
			ptr += 4;
			sprintf(buffer, "V%d", (int)ntohl(vendor));
			debug_add_string(buffer, strlen(buffer));

			left = pair->strlength - 4;
			while (left >= 2) {
				sprintf(buffer, ":T%d:L%d:", ptr[0], ptr[1]);
				debug_add_string(buffer, strlen(buffer));

				left -= 2;
				ptr += 2;
				
				i = ptr[1] - 2;
				while (i > 0 && left > 0) {
					debug_add_char(*ptr);
					ptr++;
					i--;
					left--;
				}
			}
		}
		debug_add_char('"');
		break;

	case PW_TYPE_INTEGER:
		dval = dict_valget(pair->lvalue, pair->name);
		if (dval != (DICT_VALUE *)NULL) {
			debug_add_string(dval->name, strlen(dval->name));
		} else {
			sprintf(buffer, "%ld", (long)pair->lvalue);
			debug_add_string(buffer, strlen(buffer));
		}
		break;

	case PW_TYPE_IPADDR:
		ipaddr2str(buffer, pair->lvalue);
		debug_add_string(buffer, strlen(buffer));
		break;

	case PW_TYPE_DATE:
		strftime(buffer, sizeof(buffer), "%b %e %Y",
			 localtime((time_t *)&pair->lvalue));
		debug_add_string(buffer, strlen(buffer));
		break;

	default:
		sprintf(buffer, "(unknown type %d)", pair->type);
		debug_add_string(buffer, strlen(buffer));
		break;
	}

	ptr = debug_finish_string();
	return ptr;
}

#endif

#ifdef USE_SQL
void
sqllog(status, msg, va_alist)
	int status;
	char *msg;
	va_dcl
{
        va_list ap;
        FILE *fp;
	char *path;
	char *filename;

	filename = status ? "sql-lost" : "sql.log";
        path = mkfilename(radacct_dir, filename);
        if ((fp = fopen(path, "a")) == NULL) {
                radlog(L_ERR|L_PERROR, _("could not append to file %s"), path);
		efree(path);
                return;
        }
	efree(path);
        va_start(ap);
        vfprintf(fp, msg, ap);
        fprintf(fp, ";\n");
        va_end(ap);
        fclose(fp);
}
#endif

