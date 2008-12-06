/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <radiusd.h>
#include <rewrite.h>

static int logging_category = GRAD_LOG_CAT(GRAD_LOG_MAIN);
static grad_list_t /* of Channel*/ *chanlist;   /* List of defined channels */
static char *log_prefix_hook;             /* Name of the global prefix hook */
static char *log_suffix_hook;             /* Name of the global suffix hook */

#define SP(p) ((p)?(p):"")

struct log_data {
	int cat;
	int pri;
	const grad_request_t *req;
	const char *prefix;
	const char *text;
	const char *errtext;
};



struct logbuf {
	char *ptr;
	size_t size;
	size_t pos;
};

#define LOGBUF_INIT(b) { (b), sizeof(b), 0 }
#define _log_s_cat2__(a,b) a ## b 
#define LOGBUF_DECL(name,size) \
  static char _log_s_cat2__(name,_buffer)[ size ];\
  struct logbuf name = LOGBUF_INIT(_log_s_cat2__(name,_buffer))

void
logbuf_append(struct logbuf *buf, const char *str)
{
	size_t length = strlen(str);
	size_t rest = buf->size - buf->pos;

	if (rest <= 1) 
		buf->ptr[buf->pos-1] = '>';
	else if (rest == 2)
		buf->ptr[buf->pos++] = '>';
	else if (length >= rest) {
		if (--rest > 1) {
			if (rest >= 2)
				rest--;
			memcpy(buf->ptr + buf->pos, str, rest);
			buf->pos += rest;
		} 
		buf->ptr[buf->pos++] = '>';
	} else {
		memcpy(buf->ptr + buf->pos, str, length);
		buf->pos += length;
	}
}

void
logbuf_append_line(struct logbuf *buf, size_t line)
{
	char linestr[64];
	snprintf(linestr, sizeof(linestr), "%lu", (unsigned long)line);
	logbuf_append(buf, linestr);
}

void
logbuf_vformat(struct logbuf *buf, const char *fmt, va_list ap)
{
	size_t rest = buf->size - buf->pos;
	size_t length;
	int n;
	
	if (rest <= 1)
		return;

	n = vsnprintf(buf->ptr + buf->pos, rest, fmt, ap);
	length = strlen (buf->ptr + buf->pos);
	buf->pos += length;
	if (n == -1 || length < n)
		buf->ptr[buf->pos-1] = '>';
}

char *
logbuf_ptr(struct logbuf *buf)
{
	buf->ptr[buf->pos] = 0;
	return buf->ptr;
}

size_t
logbuf_printable_length(struct logbuf *buf)
{
	return buf->pos;
}


static int
log_get_category()
{
        return logging_category;
}

static void
log_set_category(int cat)
{
        logging_category = GRAD_LOG_CAT(cat);
}

void
log_open(int cat)
{
        log_set_category(cat);
}

void
log_close()
{
        log_set_category(GRAD_LOG_MAIN);
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

static char *
run_log_hook(const grad_request_t *req, const char *hook_name)
{
	grad_value_t val;
	char nasbuf[GRAD_MAX_LONGNAME];

	memset(&val, 0, sizeof(val));

	/* FIXME: Should make sure that the hook does not modify the
	   request, either by passing rewrite_invoke a copy of the
	   latter (expensive), or by providing some internal rewrite
	   mechanism */
	if (rewrite_invoke(String,
			   &val,
			   hook_name,
			   req,
			   "isi",
			   req->code,
			   grad_nas_request_to_name(req,
						    nasbuf, sizeof nasbuf),
			   req->id))
		return NULL;
	return val.datum.sval.data;
}

static void
log_format_hook(struct logbuf *bufp, char **hook_name_ptr,
		const grad_request_t *req)
{
	char *hook_res = NULL;

	if (*hook_name_ptr) {
		hook_res = run_log_hook(req, *hook_name_ptr);
		if (!hook_res) 
			*hook_name_ptr = NULL;
	}

	if (hook_res) {
		logbuf_append(bufp, hook_res);
		grad_free(hook_res);
	}
}

static FILE *
channel_open_file(Channel *chan)
{
        FILE *fp = NULL;

        if (strcmp(chan->id.file, "stdout"))
                fp = fopen(chan->id.file, "a");
        return fp ? fp : stderr;
}

/*ARGSUSED*/
static void
channel_close_file(Channel *chan, FILE *fp)
{
        if (fp != stderr)
                fclose(fp);
}

int
log_to_channel(void *item, void *pdata)
{
	Channel *chan = item;
	struct log_data *data = pdata;

	LOGBUF_DECL(pri_prefix, 64);
	LOGBUF_DECL(req_prefix, 256);
	LOGBUF_DECL(req_suffix, 256);
	
        time_t  timeval;
        char buffer[256];
        struct tm *tm, tms;
        int spri;
        FILE *fp;

	if (!(chan->pmask[data->cat] & GRAD_LOG_MASK(data->pri)))
		return 0;
	
        if (chan->options & LO_CAT) {
		logbuf_append(&pri_prefix, _(catname[data->cat]));
		logbuf_append(&pri_prefix, ".");
	}
        if (chan->options & LO_PRI)
		logbuf_append(&pri_prefix, _(priname[data->pri]));

  	if (data->req) {
		log_format_hook(&req_prefix,
				chan->prefix_hook ?
 				   &chan->prefix_hook : &log_prefix_hook,
				data->req);
 		log_format_hook(&req_suffix,
				chan->suffix_hook ?
				   &chan->suffix_hook : &log_suffix_hook,
				data->req);
	}
	
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
                        fprintf(fp, "[%lu]: ", (u_long) getpid());
                if (logbuf_printable_length(&pri_prefix))
                        fprintf(fp, "%s: ", logbuf_ptr(&pri_prefix));
                if (data->prefix)
                        fprintf(fp, "%s", data->prefix);
		if (logbuf_printable_length(&req_prefix))
			fprintf(fp, "%s", logbuf_ptr(&req_prefix));
                if (data->text)
                        fprintf(fp, "%s", data->text);
                if (data->errtext)
                        fprintf(fp, ": %s", data->errtext);
		if (logbuf_printable_length(&req_suffix))
			fprintf(fp, "%s", logbuf_ptr(&req_suffix));
                fprintf(fp, "\n");
                channel_close_file(chan, fp);
                break;
                
        case LM_SYSLOG:
                spri = chan->id.sl.prio;
                openlog(chan->id.sl.tag ? chan->id.sl.tag : "radiusd",
			(chan->options & LO_PID) ? LOG_PID : 0,
			chan->id.sl.fac);
                if (logbuf_printable_length(&pri_prefix)) {
			if (data->errtext)
				syslog(spri, "%s: %s%s%s: %s%s",
				       logbuf_ptr(&pri_prefix),
				       SP(data->prefix),
				       logbuf_ptr(&req_prefix),
				       SP(data->text),
				       data->errtext,
				       logbuf_ptr(&req_suffix));
			else
				syslog(spri, "%s: %s%s%s%s",
				       logbuf_ptr(&pri_prefix),
				       SP(data->prefix),
				       logbuf_ptr(&req_prefix),
				       SP(data->text),
 				       logbuf_ptr(&req_suffix));
		} else {
			if (data->errtext)
				syslog(spri, "%s%s%s: %s%s",
				       SP(data->prefix),
				       logbuf_ptr(&req_prefix),
				       SP(data->text),
				       data->errtext,
				       logbuf_ptr(&req_suffix));
			else
				syslog(spri, "%s%s%s%s",
				       SP(data->prefix),
				       logbuf_ptr(&req_prefix),
				       SP(data->text),
				       logbuf_ptr(&req_suffix));
		}
                break;
        }
	return 0;
}

/* Note: if modifying this function, make sure it does not allocate any
   memory! */
void
radiusd_logger(int level,
	       const grad_request_t *req,
	       const grad_locus_t *loc,
	       const char *func_name,
	       int en,
	       const char *fmt, va_list ap)
{
        Channel *chan;
        int cat, pri;
	struct log_data log_data;
	
	LOGBUF_DECL(buf1, 256);
	LOGBUF_DECL(buf2, 1024);
	
        char *errstr = NULL;

        cat = GRAD_LOG_CAT(level);
        if (cat == 0)
                cat = log_get_category();
        pri = GRAD_LOG_PRI(level);
        
        if (loc && loc->file) {
		logbuf_append(&buf1, loc->file);
		logbuf_append(&buf1, ":");
		logbuf_append_line(&buf1, loc->line);
		if (func_name) {
			logbuf_append(&buf1, ":");			
			logbuf_append(&buf1, func_name);
		}
		logbuf_append(&buf1, ": ");			
	}
	
        if (en)
                errstr = strerror(en);

        logbuf_vformat(&buf2, fmt, ap);

        log_data.cat = cat;
	log_data.pri = pri;
	log_data.req = req;
	log_data.prefix = logbuf_ptr(&buf1);
	log_data.text = logbuf_ptr(&buf2);
	log_data.errtext = errstr;

 	grad_list_iterate(chanlist, log_to_channel, &log_data);
}

/* Interface */

#ifdef USE_SQL
void
sqllog(int status, char *query)
{
        FILE *fp;
        char *path;
        char *filename;

        filename = status ? "sql-lost" : "sql.log";
        path = grad_mkfilename(grad_acct_dir, filename);
        if ((fp = fopen(path, "a")) == NULL) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,  
                         _("could not append to file %s"), path);
                grad_free(path);
                return;
        }
        grad_free(path);
        fprintf(fp, "%s;\n", query);
        fclose(fp);
}
#endif

/* Registering functions */

void
channel_free(Channel *chan)
{
        grad_free(chan->name);
        if (chan->mode == LM_FILE)
                grad_free(chan->id.file);
	else
		grad_free(chan->id.sl.tag); 
	grad_free(chan->prefix_hook);
	grad_free(chan->suffix_hook);
        grad_free(chan);
}

Channel *
log_mark()
{
        return grad_list_item(chanlist, 0);
}

void
log_release(Channel *chan)
{
        Channel *cp;
        int emerg, alert, crit;
	grad_iterator_t *itr = grad_iterator_create(chanlist);

	for (cp = grad_iterator_first(itr); cp; cp = grad_iterator_next(itr))
		if (cp == chan)
			break;
        for (; cp; cp = grad_iterator_next(itr)) {
                if (!(cp->options & LO_PERSIST)) {
			grad_list_remove(chanlist, cp, NULL);
                        channel_free(cp);
                }
        }

        /* Make sure we have at least a channel for categories below
           GRAD_LOG_CRIT */
        emerg = GRAD_LOG_EMERG;
        alert = GRAD_LOG_ALERT;
        crit  = GRAD_LOG_CRIT;
	for (cp = grad_iterator_first(itr); cp; cp = grad_iterator_next(itr)) {
                int i;
                for (i = 1; i < GRAD_LOG_NCAT; i++) {
                        if (emerg && (cp->pmask[i] & GRAD_LOG_MASK(emerg)))
                                emerg = 0;
                        if (alert && (cp->pmask[i] & GRAD_LOG_MASK(alert)))
                                alert = 0;
                        if (crit && (cp->pmask[i] & GRAD_LOG_MASK(crit)))
                                crit = 0;
                }
        }
	grad_iterator_destroy(&itr);
        if (emerg || alert || crit)
                log_set_default("##emerg##", -1, emerg|alert|crit);
}

int
log_change_owner(RADIUS_USER *usr)
{
        Channel *cp;
	int errcnt = 0;
	grad_iterator_t *itr = grad_iterator_create(chanlist);
	for (cp = grad_iterator_first(itr); cp; cp = grad_iterator_next(itr)) {
		if (cp->mode == LM_FILE
		    && chown(cp->id.file, usr->uid, usr->gid)) {
			grad_log(GRAD_LOG_ERR,
			         _("%s: cannot change owner to %d:%d"),
			         cp->id.file, usr->uid, usr->gid);
			errcnt++;
		}
	}
	grad_iterator_destroy(&itr);
	return errcnt;
}

static int
_chancmp(const void *item, const void *data)
{
	const Channel *chan = item;
	const char *name = data;
        return strcmp(chan->name, name);
}

Channel *
channel_lookup(char *name)
{
        return grad_list_locate(chanlist, name, _chancmp);
}

void
register_channel(Channel *chan)
{
        FILE *fp;
        Channel *channel;
        char *filename;

        if (chan->mode == LM_FILE) {
                if (strcmp(chan->id.file, "stdout")) {
                        filename = grad_mkfilename(grad_log_dir ?
						   grad_log_dir : RADLOG_DIR,
						   chan->id.file);
                        
                        /* check the accessibility of the file */
                        fp = fopen(filename, "a");
                        if (!fp) {
                                grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR,
                                         _("can't access log file `%s'"),
                                         filename);
                                grad_free(filename);
                                filename = grad_estrdup("stdout");
                        } else
                                fclose(fp);
                } else
                        filename = grad_estrdup("stdout");
        } else if (chan->mode == LM_SYSLOG) {
        } 

        channel = grad_emalloc(sizeof(*channel));
        channel->name = grad_estrdup(chan->name);
        channel->mode = chan->mode;
        if (chan->mode == LM_FILE)
                channel->id.file = filename;
        else if (chan->mode == LM_SYSLOG) {
                channel->id.sl.prio = chan->id.sl.prio;
		channel->id.sl.fac  = chan->id.sl.fac;
		channel->id.sl.tag = chan->id.sl.tag ?
			                grad_estrdup(chan->id.sl.tag) : NULL;
	}
        channel->options = chan->options;
	channel->prefix_hook = chan->prefix_hook;
	channel->suffix_hook = chan->suffix_hook;
	
	if (!chanlist)
		chanlist = grad_list_create();
	grad_list_prepend(chanlist, channel);
}

void
register_category0(int cat, int pri, Channel *chan)
{
	if (cat == -1) {
		int i;
		for (i = 0; i < GRAD_LOG_NCAT; i++)
			chan->pmask[i] |= pri;
	} else
		chan->pmask[GRAD_LOG_CAT(cat)] |= pri;
}

struct category_closure {
	int cat;
	int pri;
};

static int 
_regcat(void *item, void *data)
{
	Channel *chan = item;
	struct category_closure *cp = data;
	register_category0(cp->cat, cp->pri, chan);
	return 0;
}

void
register_category(int cat, int pri, grad_list_t *clist)
{
	struct category_closure clos;

        if (pri == -1)
                pri = GRAD_LOG_UPTO(GRAD_LOG_DEBUG);

	clos.cat = cat;
	clos.pri = pri;
	grad_list_iterate(clist, _regcat, &clos);
}

/* Auxiliary calls */
void
log_set_to_console(int cat, int pri)
{
        Channel chan;
        
        chan.mode = LM_FILE;
        chan.name = "stdout";
        chan.id.file = "stdout";
        chan.options = LO_CAT|LO_PRI|LO_PERSIST;
        register_channel(&chan);

        register_category0(cat, pri, channel_lookup("stdout"));
}

void
log_set_default(char *name, int cat, int pri)
{
        Channel chan;
        
        chan.mode = LM_FILE;
        chan.name = name;
        chan.id.file = "radius.log";
        chan.options = LO_CAT|LO_PRI;
	chan.prefix_hook = chan.suffix_hook = NULL;
	
        if (!channel_lookup(name))
                register_channel(&chan);
        register_category0(cat, pri, channel_lookup(name));
}


void
format_exit_status(char *buffer, int buflen, int status)
{
	if (WIFEXITED(status)) {
		snprintf(buffer, buflen,
/* TRANSLATORS: the subject will always be printed before this msgid.
   for example: "child 222 exited with status 0"
*/
			 _("exited with status %d"),
			 WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		snprintf(buffer, buflen,
/* TRANSLATORS: the subject will always be printed before this msgid. */
			 _("terminated on signal %d"),
			 WTERMSIG(status));
	} else
/* TRANSLATORS: the subject will always be printed before this msgid. */
		snprintf(buffer, buflen, _("terminated"));
}


/* ************************************************************************* */
/* Configuration issues */

static Channel *mark, channel;
static struct category_def {
	int init;
	int cat;
	int pri;
        grad_list_t /* of Channel */ *clist;
        int level;
} cat_def;

static grad_keyword_t syslog_facility[] = {
	{ "user", 	LOG_USER },
	{ "daemon", 	LOG_DAEMON },
	{ "auth", 	LOG_AUTH },
	{ "local0", 	LOG_LOCAL0 },
	{ "local1", 	LOG_LOCAL1 },
	{ "local2", 	LOG_LOCAL2 },
	{ "local3", 	LOG_LOCAL3 },
	{ "local4", 	LOG_LOCAL4 },
	{ "local5", 	LOG_LOCAL5 },
	{ "local6", 	LOG_LOCAL6 },
	{ "local7", 	LOG_LOCAL7 },
	{ 0 }
};

static grad_keyword_t syslog_priority[] = {
	{ "emerg", 	LOG_EMERG },
	{ "alert", 	LOG_ALERT },
	{ "crit", 	LOG_CRIT },
	{ "err", 	LOG_ERR },
	{ "warning", 	LOG_WARNING },
	{ "notice", 	LOG_NOTICE },
	{ "info", 	LOG_INFO },
	{ "debug", 	LOG_DEBUG },
	{ 0 }
};

static grad_keyword_t log_categories[] = {
	{ "main",       GRAD_LOG_MAIN },
	{ "auth",       GRAD_LOG_AUTH },
	{ "acct",       GRAD_LOG_ACCT },
	{ "snmp",       GRAD_LOG_SNMP },
	{ "proxy",      GRAD_LOG_PROXY },
	{ 0 }
};

static grad_keyword_t log_priorities[] = {
	{ "emerg",      GRAD_LOG_EMERG },
	{ "alert",      GRAD_LOG_ALERT },
	{ "crit",       GRAD_LOG_CRIT },
	{ "err",        GRAD_LOG_ERR },
	{ "warning",    GRAD_LOG_WARN },
	{ "notice",     GRAD_LOG_NOTICE },
	{ "info",       GRAD_LOG_INFO },
	{ "debug",      GRAD_LOG_DEBUG },
	{ 0 }
};

int
logging_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
		     void *handler_data)
{
	mark = log_mark();
	grad_free(log_prefix_hook);
	log_prefix_hook = NULL;
	grad_free(log_suffix_hook);
	log_suffix_hook = NULL;
	return 0;
}


int
logging_stmt_end(void *block_data, void *handler_data)
{
	log_release(mark);
	return 0;
}

int
logging_stmt_begin(int finish, void *block_data, void *handler_data)
{
	/*nothing to do?*/
	return 0;
}

static int
channel_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
		     void *handler_data)
{
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	
	memset(&channel, 0, sizeof(channel));
	channel.mode = LM_UNKNOWN;
	channel.name = argv[1].v.string;
	return 0;
}

static int
channel_stmt_end(void *block_data, void *handler_data)
{
	if (channel.mode == LM_UNKNOWN) {
		grad_log(GRAD_LOG_ERR,
		         _("%s:%d: no channel mode for `%s'"), 
		         cfg_filename, cfg_line_num, channel.name);
	} else 
		register_channel(&channel);
	return 0;
}

static int
get_priority(cfg_value_t *argv)
{
	if (argv[0].type != CFG_CHAR || argv[1].type != CFG_STRING)
		return 1;
	cat_def.pri = grad_xlat_keyword(log_priorities,
					argv[1].v.string,
					-1);
	if (cat_def.pri == -1)
		return 1;

	switch (argv[0].v.ch) {
	case '!':
		cat_def.pri = GRAD_LOG_UPTO(GRAD_LOG_DEBUG) & ~GRAD_LOG_MASK(cat_def.pri);
		break;

	case '=':
		cat_def.pri = GRAD_LOG_MASK(cat_def.pri);
		break;

	default:
		return 1;
	}
	return 0;
}	

static int
category_stmt_handler(int argc, cfg_value_t *argv,
		      void *block_data, void *handler_data)
{
	cat_def.init = 0;
	cat_def.cat = cat_def.pri = -1;
	cat_def.level = 0;
	
	switch (argc) {
	case 2: /* only category or priority */
		switch (argv[1].type) {
		case CFG_CHAR:
			if (argv[1].v.ch == '*') 
				cat_def.cat = cat_def.pri = -1;
			else
				return 1;
			break;
			
		case CFG_STRING:
			cat_def.cat = grad_xlat_keyword(log_categories,
							argv[1].v.string, -1);
			if (cat_def.cat == -1) {
				cat_def.pri = grad_xlat_keyword(log_priorities,
							      argv[1].v.string,
								-1);
				if (cat_def.pri == -1)
					return 1;
				cat_def.pri = GRAD_LOG_UPTO(cat_def.pri);
			}
		}
		break;

	case 3: /* [!=]priority */
		if (get_priority(argv+1))
			return 1;
		break;

	case 4: /* category '.' priority */
		if (!(argv[2].type == CFG_CHAR && argv[2].v.ch == '.'))
			return 1;

		switch (argv[1].type) {
		case CFG_CHAR:
			if (argv[1].v.ch == '*')
				cat_def.cat = -1;
			else
				return 1;
			break;
			
		case CFG_STRING:
			cat_def.cat = grad_xlat_keyword(log_categories,
							argv[1].v.string, -1);
			if (cat_def.cat == -1) 
				return 1;
			break;

		default:
			return 1;
		}

		switch (argv[3].type) {
		case CFG_CHAR:
			if (argv[3].v.ch == '*')
				cat_def.pri = -1;
			else
				return 1;
			break;
			
		case CFG_STRING:
			cat_def.pri = grad_xlat_keyword(log_priorities,
							argv[3].v.string, -1);
			if (cat_def.pri == -1) 
				return 1;
			cat_def.pri = GRAD_LOG_UPTO(cat_def.pri);
			break;

		default:
			return 1;
		}
		break;

	case 5: /* category '.' [!=] priority */
		if (!(argv[2].type == CFG_CHAR && argv[2].v.ch == '.'))
			return 1;

		switch (argv[1].type) {
		case CFG_CHAR:
			if (argv[1].v.ch == '*')
				cat_def.cat = -1;
			else
				return 1;
			break;
			
		case CFG_STRING:
			cat_def.cat = grad_xlat_keyword(log_categories,
							argv[1].v.string, -1);
			if (cat_def.cat == -1) 
				return 1;
			break;

		default:
			return 1;
		}

		if (get_priority(argv+3))
			return 1;
		break;

	default:
		cfg_argc_error(0);
		return 0;
	}
	cat_def.init = 1;
	cat_def.clist = NULL;
	return 0;
}

static int
category_stmt_end(void *block_data, void *handler_data)
{
	if (cat_def.init) {
		switch (cat_def.cat) {
		case GRAD_LOG_AUTH:
			log_mode = cat_def.level;
			break;
		default:
			if (cat_def.level)
				grad_log(GRAD_LOG_WARN,
				         "%s:%d: %s",
				         cfg_filename, cfg_line_num,
				_("no levels applicable for this category"));
		}
		register_category(cat_def.cat, cat_def.pri, cat_def.clist);
		grad_list_destroy(&cat_def.clist, NULL, NULL);
	}
	return 0;
}

static int
category_set_channel(int argc, cfg_value_t *argv,
		     void *block_data, void *handler_data)
{
	Channel *channel;
		
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	channel = channel_lookup(argv[1].v.string);

	if (!channel) {
		grad_log(GRAD_LOG_ERR,
		         _("%s:%d: channel `%s' not defined"),
		         cfg_filename, cfg_line_num, argv[1].v.string);
	} else {
		if (!cat_def.clist)
			cat_def.clist = grad_list_create();
		grad_list_append(cat_def.clist, channel);
	}
	
	return 0;
}

static int
category_set_flag(int argc, cfg_value_t *argv, void *block_data,
		  void *handler_data)
{
	int flag = (int) handler_data;
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
 	if (argv[1].type != CFG_BOOLEAN) {
		cfg_type_error(CFG_BOOLEAN);
		return 0;
	}
	if (argv[1].v.bool)
		cat_def.level |= flag;
	else
		cat_def.level &= ~flag;
	return 0;
}

static int
category_set_level(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data)
{
	int i;

	grad_clear_debug();
	for (i = 1; i < argc; ) {
		char *modname;
		int level;
		
		if (argv[i].type != CFG_STRING) {
			grad_log(GRAD_LOG_ERR,
			         _("%s:%d: list item %d has wrong datatype"),
			         cfg_filename, cfg_line_num,
			         i);
			return 1;
		}
		modname = argv[i++].v.string;
		level = -1;
		if (i < argc
		    && argv[i].type == CFG_CHAR && argv[i].v.ch == '=') {
			i++;
			if (i == argc || argv[i].type != CFG_INTEGER)
				return 1;
			level = argv[i++].v.number;
		}
		if (grad_set_module_debug_level(modname, level)) {
			grad_log(GRAD_LOG_WARN,
			         _("%s:%d: no such module name: %s"),
			         cfg_filename, cfg_line_num, modname);
		}
	}
	return 0;
}

static int
channel_file_handler(int argc, cfg_value_t *argv, void *block_data,
		     void *handler_data)
{
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	channel.mode = LM_FILE;
	channel.id.file = argv[1].v.string;
	return 0;
}

static int
channel_syslog_handler(int argc, cfg_value_t *argv, void *block_data,
		       void *handler_data)
{
	int facility;
	int prio;
	
	if (argc < 4 || argc > 5) {
		cfg_argc_error(argc < 4);
		return 0;
	}

	switch (argv[1].type) {
	case CFG_INTEGER:
		facility = argv[1].v.number;
		break;

	case CFG_STRING:
		facility = grad_xlat_keyword(syslog_facility,
					     argv[1].v.string, -1);
		break;

	default:
		return 1;
	}

	if (facility == -1)
		return 1;

	if (argv[2].type != CFG_CHAR || argv[2].v.ch != '.')
		return 1;
	
	switch (argv[3].type) {
	case CFG_INTEGER:
		prio = argv[3].v.number;
		break;

	case CFG_STRING:
		prio = grad_xlat_keyword(syslog_priority,
					 argv[3].v.string, -1);
		break;

	default:
		return 1;
	}

	if (prio == -1)
		return 1;
	
	if (argc == 5) {
		if (argv[4].type != CFG_STRING) {
			cfg_type_error(CFG_STRING);
			return 0;
		}
		channel.id.sl.tag = argv[4].v.string;
	} else
		channel.id.sl.tag = NULL;
	channel.mode = LM_SYSLOG;
	channel.id.sl.prio = prio;
	channel.id.sl.fac = facility;
	return 0;
}

static int
channel_set_flag(int argc, cfg_value_t *argv,
		 void *block_data, void *handler_data)
{
	int flag = (int) handler_data;
	if (argc != 2) {
		cfg_argc_error(argc < 2);
		return 0;
	}
 	if (argv[1].type != CFG_BOOLEAN) {
		cfg_type_error(CFG_BOOLEAN);
		return 0;
	}

	if (argv[1].v.bool)
		channel.options |= flag;
	else
		channel.options &= ~flag;
	return 0;
}

static struct cfg_stmt channel_stmt[] = {
	{ "file", CS_STMT, NULL, channel_file_handler, NULL, NULL, NULL },
	{ "syslog", CS_STMT, NULL, channel_syslog_handler, NULL, NULL, NULL },
	{ "print-pid", CS_STMT, NULL, channel_set_flag, (void*)LO_PID,
	  NULL, NULL },
	{ "print-cons", CS_STMT, NULL, channel_set_flag, (void*)LO_CONS,
	  NULL, NULL },
	{ "print-level", CS_STMT, NULL, channel_set_flag, (void*)LO_PRI,
	  NULL, NULL },
	{ "print-category", CS_STMT, NULL, channel_set_flag, (void*)LO_CAT,
	  NULL, NULL },
	{ "print-priority", CS_STMT, NULL, channel_set_flag, (void*)LO_PRI,
	  NULL, NULL },
	{ "print-milliseconds", CS_STMT, NULL, channel_set_flag,
	  (void*)LO_MSEC, NULL, NULL },
	{ "prefix-hook", CS_STMT, NULL, cfg_get_string, &channel.prefix_hook,
	  NULL, NULL },
	{ "suffix-hook", CS_STMT, NULL, cfg_get_string, &channel.suffix_hook,
	  NULL, NULL },
	{ NULL }
};

static struct cfg_stmt category_stmt[] = {
	{ "channel", CS_STMT, NULL, category_set_channel, NULL, NULL, NULL },
	{ "print-auth", CS_STMT, NULL,
	  category_set_flag, (void*)RLOG_AUTH, NULL, NULL },
	{ "print-failed-pass", CS_STMT, NULL,
	  category_set_flag, (void*)RLOG_FAILED_PASS, NULL, NULL },
	{ "print-pass", CS_STMT, NULL,
	  category_set_flag, (void*)RLOG_AUTH_PASS, NULL, NULL },
	{ "level", CS_STMT, NULL,
	  category_set_level, NULL, NULL, NULL },
	{ NULL }
};

struct cfg_stmt logging_stmt[] = {
	{ "channel", CS_BLOCK, NULL,
	  channel_stmt_handler, NULL, channel_stmt, channel_stmt_end },
	{ "category", CS_BLOCK, NULL,
	  category_stmt_handler, NULL, category_stmt, category_stmt_end }, 
	{ "prefix-hook", CS_STMT, NULL, cfg_get_string, &log_prefix_hook,
	  NULL, NULL },
	{ "suffix-hook", CS_STMT, NULL, cfg_get_string, &log_suffix_hook,
	  NULL, NULL },
	{ NULL },
};

