/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

static int logging_category = L_CAT(L_MAIN);
static LIST /* of Channel*/ *chanlist;     /* List of defined channels */

static void log_to_channel(Channel *chan, int cat, int pri,
                           char *buf1, char *buf2, char *buf3);
void vlog(int lvl, char *file, int line, char *func_name, int en,
          char *fmt, va_list ap);
static FILE *channel_open_file(Channel *chan);
static void channel_close_file(Channel *chan, FILE *fp);

#define SP(p) ((p)?(p):"")

static int
log_get_category()
{
        return logging_category;
}

static void
log_set_category(int cat)
{
        logging_category = L_CAT(cat);
}

void
log_open(int cat)
{
        log_set_category(cat);
}

void
log_close()
{
        log_set_category(L_MAIN);
}

void
vlog(int level, char *file, int line, char *func_name,
     int en, char *fmt, va_list ap)
{
        Channel *chan;
        int cat, pri;
        char *buf1 = NULL;
        char *buf2 = NULL;
        char *buf3 = NULL;
	ITERATOR *itr = iterator_create(chanlist);

        cat = L_CAT(level);
        if (cat == 0)
                cat = log_get_category();
        pri = L_PRI(level);
        
        if (file) 
                asprintf(&buf1, "%s:%d:%s: ", file, line, SP(func_name));
        if (en)
                asprintf(&buf3, ": %s", strerror(en));

        vasprintf(&buf2, fmt, ap);
        
        for (chan = iterator_first(itr); chan; chan = iterator_next(itr)) {
                /* Skip channels whith incorrect priority */
                if (chan->pmask[cat] & L_MASK(pri))
                        log_to_channel(chan, cat, pri, buf1, buf2, buf3);
        }
        iterator_destroy(&itr);

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
log_to_channel(Channel *chan, int cat, int pri,
	       char *buf1, char *buf2, char *buf3)
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
channel_open_file(Channel *chan)
{
        FILE *fp = NULL;

        if (strcmp(chan->id.file, "stdout"))
                fp = fopen(chan->id.file, "a");
        return fp ? fp : stderr;
}

/*ARGSUSED*/
void
channel_close_file(Channel *chan, FILE *fp)
{
        if (fp != stderr)
                fclose(fp);
}

/* Interface */

#ifdef USE_SQL
/*PRINTFLIKE2*/
void
sqllog(int status, char *msg, ...)
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
	va_start(ap, msg);
        vfprintf(fp, msg, ap);
        fprintf(fp, ";\n");
        va_end(ap);
        fclose(fp);
}
#endif

/* Registering functions */

void
channel_free(Channel *chan)
{
        efree(chan->name);
        if (chan->mode == LM_FILE)
                efree(chan->id.file);
        efree(chan);
}

Channel *
log_mark()
{
        return list_item(chanlist, 0);
}

void
log_release(Channel *chan)
{
        Channel *cp, *prev = NULL;
        int emerg, alert, crit;
	ITERATOR *itr = iterator_create(chanlist);

	for (cp = iterator_first(itr); cp; cp = iterator_next(itr))
		if (cp == chan)
			break;
        for (; cp; cp = iterator_next(itr)) {
                if (!(cp->options & LO_PERSIST)) {
			list_remove(chanlist, cp, NULL);
                        channel_free(cp);
                }
        }

        /* Make sure we have at least a channel for categories below
           L_CRIT */
        emerg = L_EMERG;
        alert = L_ALERT;
        crit  = L_CRIT;
	for (cp = iterator_first(itr); cp; cp = iterator_next(itr)) {
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
	iterator_destroy(&itr);
        if (emerg || alert || crit)
                log_set_default("##emerg##", -1, emerg|alert|crit);
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
        return list_locate(chanlist, name, _chancmp);
}

void
register_channel(Channel *chan)
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

        channel = emalloc(sizeof(*channel));
        channel->name = estrdup(chan->name);
        channel->mode = chan->mode;
        if (chan->mode == LM_FILE)
                channel->id.file = filename;
        else if (chan->mode == LM_SYSLOG)
                channel->id.prio = chan->id.prio;
        channel->options = chan->options;

	if (!chanlist)
		chanlist = list_create();
	list_prepend(chanlist, channel);
}

void
register_category0(int cat, int pri, Channel *chan)
{
	if (cat == -1) {
		int i;
		for (i = 0; i < L_NCAT; i++)
			chan->pmask[i] |= pri;
	} else
		chan->pmask[L_CAT(cat)] |= pri;
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
register_category(int cat, int pri, LIST *clist)
{
        Channel *chan;
	struct category_closure clos;

        if (pri == -1)
                pri = L_UPTO(L_DEBUG);

	clos.cat = cat;
	clos.pri = pri;
	list_iterate(clist, _regcat, &clos);
}

/* Auxiliary calls */
void
log_set_to_console()
{
        Channel chan;
        
        chan.mode = LM_FILE;
        chan.name = "stdout";
        chan.id.file = "stdout";
        chan.options = LO_CAT|LO_PRI|LO_PERSIST;
        register_channel(&chan);

        register_category0(-1, -1, channel_lookup("stdout"));
}

void
log_set_default(char *name, int cat, int pri)
{
        Channel chan;
        
        chan.mode = LM_FILE;
        chan.name = name;
        chan.id.file = "radius.log";
        chan.options = LO_CAT|LO_PRI;

        if (!channel_lookup(name))
                register_channel(&chan);
        register_category0(cat, pri, channel_lookup(name));
}


void
format_exit_status(char *buffer, int buflen, int status)
{
	if (WIFEXITED(status)) {
		snprintf(buffer, buflen,
			 _("exited with status %d"),
			 WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		snprintf(buffer, buflen,
			 _("terminated on signal %d"),
			 WTERMSIG(status));
	} else
		snprintf(buffer, buflen, _("terminated"));
}

/* ************************************************************************* */
/* Configuration issues */

static Channel *mark, channel;
static struct category_def {
	int init;
	int cat;
	int pri;
        LIST /* of Channel */ *clist;
        int level;
} cat_def;

static struct keyword syslog_facility[] = {
	"user", 	LOG_USER,
	"daemon", 	LOG_DAEMON,
	"auth", 	LOG_AUTH,
	"local0", 	LOG_LOCAL0,
	"local1", 	LOG_LOCAL1,
	"local2", 	LOG_LOCAL2,
	"local3", 	LOG_LOCAL3,
	"local4", 	LOG_LOCAL4,
	"local5", 	LOG_LOCAL5,
	"local6", 	LOG_LOCAL6,
	"local7", 	LOG_LOCAL7,
	0
};

static struct keyword syslog_priority[] = {
	"emerg", 	LOG_EMERG,
	"alert", 	LOG_ALERT,
	"crit", 	LOG_CRIT,
	"err", 		LOG_ERR,
	"warning", 	LOG_WARNING,
	"notice", 	LOG_NOTICE,
	"info", 	LOG_INFO,
	"debug", 	LOG_DEBUG,
	0
};

static struct keyword log_categories[] = {
	"main",         L_MAIN,
	"auth",         L_AUTH,
	"acct",         L_ACCT,
	"snmp",         L_SNMP,
	"proxy",        L_PROXY,
	0
};

static struct keyword log_priorities[] = {
	"emerg",        L_EMERG,
	"alert",        L_ALERT,
	"crit",         L_CRIT,
	"err",          L_ERR,
	"warning",      L_WARN,
	"notice",       L_NOTICE,
	"info",         L_INFO,
	"debug",        L_DEBUG,
	0
};

int
logging_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
		     void *handler_data)
{
	mark = log_mark();
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
	/*FIXME*/
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
		radlog(L_ERR,
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
	cat_def.pri = xlat_keyword(log_priorities,
				   argv[1].v.string,
				   -1);
	if (cat_def.pri == -1)
		return 1;

	switch (argv[0].v.ch) {
	case '!':
		cat_def.pri = L_UPTO(L_DEBUG) & ~L_MASK(cat_def.pri);
		break;

	case '=':
		cat_def.pri = L_MASK(cat_def.pri);
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
			cat_def.cat = xlat_keyword(log_categories,
						   argv[1].v.string, -1);
			if (cat_def.cat == -1) {
				cat_def.pri = xlat_keyword(log_priorities,
							   argv[1].v.string,
							   -1);
				if (cat_def.pri == -1)
					return 1;
				cat_def.pri = L_UPTO(cat_def.pri);
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
			cat_def.cat = xlat_keyword(log_categories,
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
			cat_def.pri = xlat_keyword(log_priorities,
						   argv[3].v.string, -1);
			if (cat_def.pri == -1) 
				return 1;
			cat_def.pri = L_UPTO(cat_def.pri);
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
			cat_def.cat = xlat_keyword(log_categories,
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
		case L_AUTH:
			log_mode = cat_def.level;
			break;
		default:
			if (cat_def.level)
				radlog(L_WARN,
				       "%s:%d: %s",
				       cfg_filename, cfg_line_num,
				_("no levels applicable for this category"));
		}
		register_category(cat_def.cat, cat_def.pri, cat_def.clist);
		list_destroy(&cat_def.clist, NULL, NULL);
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
		radlog(L_ERR,
		       _("%s:%d: channel `%s' not defined"),
		       cfg_filename, cfg_line_num, argv[1].v.string);
	} else {
		if (!cat_def.clist)
			cat_def.clist = list_create();
		list_append(cat_def.clist, channel);
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

	clear_debug();
	for (i = 1; i < argc; ) {
		char *modname;
		int level;
		
		if (argv[i].type != CFG_STRING) {
			radlog(L_ERR,
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
		if (set_module_debug_level(modname, level)) {
			radlog(L_WARN,
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
	
	if (argc != 4) {
		cfg_argc_error(argc < 4);
		return 0;
	}

	switch (argv[1].type) {
	case CFG_INTEGER:
		facility = argv[1].v.number;
		break;

	case CFG_STRING:
		facility = xlat_keyword(syslog_facility, argv[1].v.string, -1);
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
		prio = xlat_keyword(syslog_priority, argv[3].v.string, -1);
		break;

	default:
		return 1;
	}

	if (prio == -1)
		return 1;
	
	channel.mode = LM_SYSLOG;
	channel.id.prio = facility | prio ;
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
	{ NULL },
};

