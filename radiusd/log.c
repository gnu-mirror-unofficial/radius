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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <varargs.h>
#include <syslog.h>
#include <radiusd.h>
#include <log.h>

static int log_category;      /* Default logging category */
Channel *chanlist;            /* List of defined channels */

static void log_to_channel(Channel *chan, int cat, int pri,
			   char *buf1, char *buf2, char *buf3);
static void vlog(int lvl, char *file, int line, char *func_name, int errno,
		 char *fmt, va_list ap);
static FILE *channel_open_file(Channel *chan);
static void channel_close_file(Channel *chan, FILE *fp);

#define SP(p) ((p)?(p):"")

void
vlog(level, file, line, func_name, errno, fmt, ap)
	int level;
	char *file;
	int line;
	char *func_name;
	int errno;
	char *fmt;
	va_list ap;
{
	Channel *chan;
	int cat, pri;
	char *buf1 = NULL;
	char *buf2 = NULL;
	char *buf3 = NULL;

	cat = L_CAT(level);
	if (cat == 0)
		cat = log_category;
	pri = L_PRI(level);
	
	if (file) 
		asprintf(&buf1, "%s:%d:%s: ", file, line, SP(func_name));
	if (errno)
		asprintf(&buf3, ": %s", strerror(errno));

	asprintf(&buf2, fmt, ap);
	
	for (chan = chanlist; chan; chan = chan->next) {
		/* Skip channels whith incorrect priority */
		if (chan->pmask[cat] & L_MASK(pri))
			log_to_channel(chan, cat, pri, buf1, buf2, buf3);
	}

	if (buf1)
		free(buf1);
	if (buf2)
		free(buf2);
	if (buf3)
		free(buf3);
}

char catname[] = { /* category names */
	"none",
	"Main",
	"Auth",
	"Acct",
	"Proxy",
	"SNMP"
};

char priname[] = { /* priority names */
	"emerg",
	"alert",
	"crit",
	"error",
	"warning",
	"notice",
	"info",
	"debug"
};


void
log_to_channel(chan, cat, pri, buf1, buf2, buf3)
	Channel *chan;
	int cat, pri;
	char *buf1, *buf2, *buf3;
{
	char *cat_pref = NULL;
	char *prefix = NULL;
	time_t	timeval;
	char buffer[256];
	struct tm *tm;
	int spri;
	FILE *fp;
	
	if (chan->options & LO_CAT)
		asprintf(&cat_pref, "%s", catname[cat]);
	if (chan->options & LO_PRI) {
		if (cat_pref)
			asprintf(&prefix, "%s.%s", cat_pref, priname[pri]);
		else
			asprintf(&prefix, "%s", catname[pri]);
	} else if (cat_pref) {
		prefix = cat_pref;
		cat_pref = NULL;
	}

	if (cat_pref)
		free(cat_pref);

	switch (chan->mode) {
	case LM_FILE:
		timeval = time(NULL);
		tm = localtime(&timeval);
		strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", tm);
		fp = channel_open_file(chan);
		if (!fp) /* FIXME: log to default channel */
			break;
		fprintf(fp, "%s: ", buffer);
		if (chan->options & LO_PID) 
			fprintf(fp, "[%lu]: ", getpid());
		if (prefix)
			fprintf(fp, "%s: ", prefix);
		if (buf1)
			fprintf(fp, "%s", buf1);
		if (buf2)
			fprintf(fp, "%s", buf2);
		if (buf3)
			fprintf(fp, "%s", buf3);
		fprintf(fp, "\n");
		channel_close_file(chan, fp);
		break;
		
	case LM_SYSLOG:
		spri = chan->id.prio;
		if (chan->options & LO_PID)
			spri |= LOG_PID;
		if (prefix)
			syslog(spri, "%s: %s%s%s",
			       prefix, SP(buf1), SP(buf2), SP(buf3));
		else
			syslog(spri, "%s%s%s",
			       SP(buf1), SP(buf2), SP(buf3));
		break;
	}
	
	if (prefix)
		free(prefix);
}

FILE *
channel_open_file(chan)
	Channel *chan;
{
	FILE *fp;

	fp = fopen(chan->id.file, "a");
	return fp ? fp : stderr;
}

/*ARGSUSED*/
void
channel_close_file(chan, fp)
	Channel *chan;
	FILE *fp;
{
	if (fp != stderr)
		fclose(fp);
}

/* Interface */

/*PRINTFLIKE2*/
void
radlog(level, msg, va_alist)
	int level;
	char *msg;
	va_dcl
{
	va_list ap;
	int ec = 0;
	
	if (level & L_PERROR)
		ec = errno;
	va_start(ap);
	vlog(level, NULL, 0, NULL, ec, msg, ap);
	va_end(ap);
}

void
_debug_print(file, line, func_name, str)
	char *file;
	int line;
	char *func_name;
	char *str;
{
	vlog(L_DEBUG, file, line, func_name, 0, "%s", str);
	free(str);
}

char *
_debug_format_string(va_alist)
	va_dcl
{
	va_list ap;
	char *fmt;
	char *str = NULL;
	
	va_start(ap);
	fmt = va_arg(ap,char*);
	vasprintf(&str, fmt, ap);
	va_end(ap);
	return str;
}

void
debug_pair(prefix, pair)
	char *prefix;
	VALUE_PAIR *pair;
{
	radfprintf(stdout, "%10.10s: %A\n", prefix, pair);
}

#ifdef USE_SQL
/*PRINTFLIKE2*/
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

/* Registering functions */

Channel *
channel_lookup(name)
	char *name;
{
	Channel *chan;

	for (chan = chanlist; chan; chan = chan->next) {
		if (strcmp(chan->name, name) == 0)
			break ;
	}
	return chan;
}

void
register_channel(chan)
	Channel *chan;
{
	FILE *fp;
	Channel *channel;
	char *filename;
	
	if (chan->mode == LM_FILE) {
		if (strcmp(chan->id.file, "stdout")) {
			filename = mkfilename(radlog_dir, chan->id.file);
			
			/* check the accessibility of the file */
			fp = fopen(filename, "a");
			if (!fp) {
				radlog(L_CRIT|L_PERROR,
				       _("can't access `%s'"), filename);
				efree(filename);
				filename = estrdup("stdout");
			} else
				fclose(fp);
		} else
			filename = estrdup("stdout");
	} else if (chan->mode == LM_SYSLOG) {
	} 

	channel = alloc_entry(sizeof(*channel));
	channel->name = estrdup(chan->name);
	channel->mode = chan->mode;
	if (chan->mode == LM_FILE)
		channel->id.file = filename;
	else if (chan->mode == LM_SYSLOG)
		channel->id.prio = chan->id.prio;
	channel->options = chan->options;
	channel->next = chanlist;
	chanlist = channel;
}

void
register_category(cat, pri, chanlist)
	int cat;
	int pri;
	Chanlist *chanlist;
{
	Channel *chan;
	int primask;

	if (pri == -1)
		primask = L_PRIMASK;
	else
		primask = L_MASK(pri);
	
	for (; chanlist; chanlist = chanlist->next) {
		chan = chanlist->chan ? chanlist->chan
			 : channel_lookup("default");

		if (cat == -1) {
			int i;
			for (i = 0; i < L_NCAT; i++)
				chan->pmask[i] |= primask;
		} else
			chan->pmask[cat] |= primask;
	}
}

/* channel lists */
Chanlist *
make_chanlist(chan)
	Channel *chan;
{
	Chanlist *cl = alloc_entry(sizeof(*cl));
	cl->next = NULL;
	cl->chan = chan;
	return cl;
}
	
void
free_chanlist(cp)
	Chanlist *cp;
{
	free_slist((struct slist*)cp, NULL);
}
