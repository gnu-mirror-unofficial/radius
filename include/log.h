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

/* $Id$ */

#ifndef __log_h
#define __log_h

#include <sysdep.h>

/* The category.priority system below is constructed after that
   in <syslog.h> */
   
/* log categories */
#define L_MKCAT(n)       ((n)<<3)
#define L_MAIN           L_MKCAT(1)  /* Main server process */
#define L_AUTH           L_MKCAT(2)  /* Authentication process */
#define L_ACCT           L_MKCAT(3)  /* Accounting process */
#define L_PROXY          L_MKCAT(4)  /* Proxy */
#define L_SNMP           L_MKCAT(5)  /* SNMP process */
#define L_NCAT           8           /* Number of categories */
#define L_CATMASK        0x38        /* Mask to extract category part */

/* log priorities */
#define	L_EMERG	   0	/* system is unusable */
#define	L_ALERT	   1	/* action must be taken immediately */
#define	L_CRIT	   2	/* critical conditions */
#define	L_ERR	   3	/* error conditions */
#define	L_WARN     4	/* warning conditions */
#define	L_NOTICE   5	/* normal but signification condition */
#define	L_INFO	   6 	/* informational */
#define	L_DEBUG	   7	/* debug-level messages */
#define	L_PRIMASK  0x0007  /* mask to extract priority part */

#define L_CAT(v)   (((v)&L_CATMASK)>>3)
#define L_PRI(v)   ((v)&L_PRIMASK)
#define L_MASK(pri) (1<<(pri))
#define L_UPTO(pri) ((1<<((pri)+1))-1)
/* Additional flags */
#define L_PERROR  0x8000

/* log output modes */
#define LM_UNKNOWN -1
#define LM_OFF 0
#define LM_FILE 1
#define LM_SYSLOG 2

/* log options */
#define LO_CONS  0x0001
#define LO_PID   0x0002
#define LO_CAT   0x0004
#define LO_PRI   0x0008

int radvsprintf(/*char *string, size_t size, char *fmt, va_list ap*/);
int radsprintf(/*char *string, size_t size, char *fmt, va_alist*/);
int radfprintf(/*FILE *file, char *fmt, va_alist*/);

#define MKSTRING(x) #x 
#define insist(cond) \
 ((void) ((cond) || __insist_failure(MKSTRING(cond), __FILE__, __LINE__)))
#define insist_fail(str) \
 __insist_failure(MKSTRING(str), __FILE__, __LINE__)
	
#define RADIUS_DEBUG_BUFFER_SIZE 1024

typedef struct {
	int type;
	union {
		char string[256];
		UINT4 ipaddr;
		int number;
		int bool;
	} v;
} Value;

typedef struct channel Channel;

struct channel {
	struct channel *next;
	char *name;
	int  pmask[L_NCAT]; 
	int mode;   /* LM_ constant */
	union {
		int prio;        /* syslog: facility|priority */
		char *file;      /* file: output file name */
	} id;
	int options;
};

typedef struct chanlist Chanlist;
struct chanlist {  /* for keeping channels while parsing config file */
	Chanlist *next;
	Channel *chan;
};

/* Global variables */
extern int debug_level[];

/* Function prototypes */
void initlog(char*);
void radlog_open(int category);
void radlog_close();
void radlog(/*int, char *, ...*/);
int __insist_failure(char *, char *, int);

/* Debugging facilities */
#ifndef MAX_DEBUG_LEVEL
# define MAX_DEBUG_LEVEL 100
#endif

struct debug_module {
	char *name;
	int  modnum;
};

extern struct debug_module debug_module[];

#if RADIUS_DEBUG
# define debug_on(level) (debug_level[RADIUS_MODULE] >= level)
# define debug(level, vlist) \
   if (debug_level[RADIUS_MODULE] >= level) \
    _debug_print(__FILE__, __LINE__, __FUNCTION__, _debug_format_string vlist)
#else
# define debug_on(level) 0
# define debug(mode,vlist)
#endif

void _debug_print(char *file, int line, char *func_name, char *str);
char *_debug_format_string(/* char *fmt, ... */);
	
/* Parsing */	

Channel *channel_lookup(char *name);
void channel_free(Channel *chan);
void channel_free_list(Channel *chan);
Channel * log_mark();
void log_release();

Chanlist * make_chanlist(Channel *chan);
void free_chanlist(Chanlist *cp);

void register_channel(Channel *chan);
void register_category(int cat, int pri, Chanlist *chanlist);


void set_debug_levels(char *str);
int set_module_debug_level(char *name, int level);
void clear_debug();

void log_set_to_console();
void log_set_default(char *name, int cat, int pri);

void log_open(int cat);
void log_close();

#endif
