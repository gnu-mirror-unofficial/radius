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

/* log levels */
#define L_DBG			1
#define L_INFO			2
#define L_NOTICE                3
#define L_WARN                  4
#define L_ERR			5
#define L_CRIT                  6
#define L_AUTH                  7
#define L_PROXY                 8
#define L_CONS			0
#define L_PERROR           0x8000
#define L_MASK             0x000f

/* log output modes */
#define LM_UNKNOWN -1
#define LM_OFF 0
#define LM_FILE 1
#define LM_SYSLOG 2

/* log options */
#define LO_CONS  0x0001
#define LO_PID   0x0002
#define LO_LEVEL 0x0004

/* Log flags */
#define RLOG_AUTH               0x0001
#define RLOG_AUTH_PASS          0x0002
#define RLOG_FAILED_PASS        0x0004
#define RLOG_PID                0x0008

#define RLOG_DEFAULT            (RLOG_AUTH | RLOG_FAILED_PASS)

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

typedef struct chanlist Chanlist;
typedef struct channel Channel;

struct channel {
	struct channel *next;
	int ucnt;
	char *name;
	int mode;
	union {
		int prio;
		char *file;
	} id;
	int options;
};

struct chanlist {
	struct chanlist *next;
	Channel *channel;
};

/* log.c */
extern int debug_level[];
extern int log_mode;

void            initlog(char*);
int		radlog(/*int, char *, ...*/);
char           *debug_sprintf(/*char *, ...*/);
void            debug_output(char *, int, char *, char *);
int             __insist_failure(char *, char *, int);

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
    debug_output(__FILE__, __LINE__, __FUNCTION__, debug_sprintf vlist)
#else
# define debug_on(level) 0
# define debug(mode,vlist)
#endif

void log_init();
void log_cleanup();
Channel *register_channel(Channel *);
Channel *install_channel(char *name, int mode, int prio, char *file, int opt);
void register_category(int cat, Chanlist *chanlist);
Chanlist *make_chanlist(Channel *chan);

Channel *channel_lookup(char *name);

void set_debug_levels(char *str);
int set_module_debug_level(char *name, int level);
void clear_debug();

#endif
