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
#include <slist.h>

static pthread_once_t log_once = PTHREAD_ONCE_INIT;
static pthread_key_t log_key;
static Channel *chanlist;                  /* List of defined channels */

static void log_to_channel(Channel *chan, int cat, int pri,
                           char *buf1, char *buf2, char *buf3);
void vlog(int lvl, char *file, int line, char *func_name, int en,
          char *fmt, va_list ap);
static FILE *channel_open_file(Channel *chan);
static void channel_close_file(Channel *chan, FILE *fp);

#define SP(p) ((p)?(p):"")

static void
log_init_specific()
{
        pthread_key_create(&log_key, NULL);
}

static int
log_get_category()
{
        void *p;
        pthread_once(&log_once, log_init_specific);
        p = pthread_getspecific(log_key);
        return p ? (int) p : L_CAT(L_MAIN);
}

static void
log_set_category(cat)
        int cat;
{
        pthread_once(&log_once, log_init_specific);
        pthread_setspecific(log_key, (const void*) L_CAT(cat));
}

void
log_open(cat)
        int cat;
{
        log_set_category(cat);
}

void
log_close()
{
        log_set_category(L_MAIN);
}

void
vlog(level, file, line, func_name, en, fmt, ap)
        int level;
        char *file;
        int line;
        char *func_name;
        int en;
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
                cat = log_get_category();
        pri = L_PRI(level);
        
        if (file) 
                asprintf(&buf1, "%s:%d:%s: ", file, line, SP(func_name));
        if (en)
                asprintf(&buf3, ": %s", strerror(en));

        vasprintf(&buf2, fmt, ap);
        
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

static char *catname[] = { /* category names */
        N_("none"),
        N_("Main"),
        N_("Auth"),
        N_("Acct"),
        N_("Proxy"),
        N_("SNMP"),
};

static char *priname[] = { /* priority names */
        N_("emerg"),
        N_("alert"),
        N_("crit"),
        N_("error"),
        N_("warning"),
        N_("notice"),
        N_("info"),
        N_("debug")
};

void
log_to_channel(chan, cat, pri, buf1, buf2, buf3)
        Channel *chan;
        int cat, pri;
        char *buf1, *buf2, *buf3;
{
        char *cat_pref = NULL;
        char *prefix = NULL;
        time_t  timeval;
        char buffer[256];
        struct tm *tm, tms;
        int spri;
        FILE *fp;
        
        if (chan->options & LO_CAT)
                asprintf(&cat_pref, "%s", _(catname[cat]));
        if (chan->options & LO_PRI) {
                if (cat_pref)
                        asprintf(&prefix, "%s.%s",
				 cat_pref,
				 _(priname[pri]));
                else
                        asprintf(&prefix, "%s", _(priname[pri]));
        } else if (cat_pref) {
                prefix = cat_pref;
                cat_pref = NULL;
        }

        if (cat_pref)
                free(cat_pref);

        switch (chan->mode) {
        case LM_FILE:
                if (chan->options & LO_MSEC) {
                        struct timeval tv;
                        int len;
                        
                        gettimeofday(&tv, NULL);
                        tm = localtime_r(&tv.tv_sec, &tms);
                        strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", tm);
                        len = strlen(buffer);
                        snprintf(buffer+len, sizeof(buffer)-len,
                                 ".%06d", (int) tv.tv_usec);
                } else {
                        timeval = time(NULL);
                        tm = localtime_r(&timeval, &tms);
                        strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", tm);
                }
                fp = channel_open_file(chan);
                if (!fp) /* FIXME: log to default channel */
                        break;
                fprintf(fp, "%s ", buffer);
                if (chan->options & LO_PID) 
                        fprintf(fp, "[%lu]: ", getpid());
                if (chan->options & LO_TID) 
                        fprintf(fp, "(%#lx): ", (long) pthread_self());
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
                if (chan->options & LO_TID) 
                        snprintf(buffer, sizeof buffer, "(%#lx): ",
                                 (long) pthread_self());
                else
                        buffer[0] = 0;
                if (prefix)
                        syslog(spri, "%s%s: %s%s%s",
                               buffer, prefix, SP(buf1), SP(buf2), SP(buf3));
                else
                        syslog(spri, "%s%s%s%s",
                               buffer, SP(buf1), SP(buf2), SP(buf3));
                break;
        }
        
        if (prefix)
                free(prefix);
}

FILE *
channel_open_file(chan)
        Channel *chan;
{
        FILE *fp = NULL;

        if (strcmp(chan->id.file, "stdout"))
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

void
channel_free(chan)
        Channel *chan;
{
        efree(chan->name);
        if (chan->mode == LM_FILE)
                efree(chan->id.file);
        free_entry(chan);
}

void
channel_free_list(chan)
        Channel *chan;
{
        Channel *next;

        while (chan) {
                next = chan->next;
                channel_free(chan);
                chan = next;
        }
}

Channel *
log_mark()
{
        return chanlist;
}

void
log_release(chan)
        Channel *chan;
{
        Channel *cp, *prev = NULL;
        int emerg, alert, crit;
        
        for (cp = chanlist; cp; prev = cp, cp = cp->next)
                if (cp == chan)
                        break;

        while (cp) {
                Channel *next = cp->next;
                if (cp->options & LO_PERSIST) {
                        if (prev)
                                prev->next = cp;
                        prev = cp;
                } else {
                        channel_free(cp);
                }
                cp = next;
        }
        if (prev)
                prev->next = NULL;

        /* Make sure we have at least a channel for categories below
           L_CRIT */
        emerg = L_EMERG;
        alert = L_ALERT;
        crit  = L_CRIT;
        for (cp = chanlist; cp; cp = cp->next) {
                int i;
                for (i = 1; i < L_NCAT; i++) {
                        if (emerg && (cp->pmask[i] & L_MASK(emerg)))
                                emerg = 0;
                        if (alert && (cp->pmask[i] & L_MASK(alert)))
                                alert = 0;
                        if (crit && (cp->pmask[i] & L_MASK(crit)))
                                crit = 0;
                }
        }

        if (emerg || alert || crit)
                log_set_default("##emerg##", -1, emerg|alert|crit);
}

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
                        filename = mkfilename(radlog_dir ?
                                              radlog_dir : RADLOG_DIR,
                                              chan->id.file);
                        
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

        if (pri == -1)
                pri = L_UPTO(L_DEBUG);
        
        for (; chanlist; chanlist = chanlist->next) {
                chan = chanlist->chan ? chanlist->chan
                         : channel_lookup("default");

                if (cat == -1) {
                        int i;
                        for (i = 0; i < L_NCAT; i++)
                                chan->pmask[i] |= pri;
                } else
                        chan->pmask[L_CAT(cat)] |= pri;
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

/* Auxiliary calls */
void
log_set_to_console()
{
        Channel chan;
        Chanlist chanlist;
        
        chan.mode = LM_FILE;
        chan.name = "stdout";
        chan.id.file = "stdout";
        chan.options = LO_CAT|LO_PRI|LO_PERSIST;
        register_channel(&chan);

        chanlist.next = NULL;
        chanlist.chan = channel_lookup("stdout");
        register_category(-1, -1, &chanlist);
}

void
log_set_default(name, cat, pri)
        char *name;
        int cat;
        int pri;
{
        Channel chan;
        Chanlist chanlist;
        
        chan.mode = LM_FILE;
        chan.name = name;
        chan.id.file = "radius.log";
        chan.options = LO_CAT|LO_PRI;

        if (!channel_lookup(name))
                register_channel(&chan);

        chanlist.next = NULL;
        chanlist.chan = channel_lookup(name);
        register_category(cat, pri, &chanlist);
}


