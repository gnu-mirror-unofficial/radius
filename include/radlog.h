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

#define L_DBG			1
#define L_INFO                  2
#define L_NOTICE                3
#define L_WARNING               4  
#define L_ERROR                 5 
#define L_CRIT                  6
#define L_PANIC                 7

#define L_CONS			128

#define L_AUTH			
#define L_ACCT
#define L_PROXY



/* Log flags */
#define RLOG_AUTH               0x0001
#define RLOG_AUTH_PASS          0x0002
#define RLOG_FAILED_PASS        0x0004
#define RLOG_AUTH_DETAIL        0x0008
#define RLOG_STRIPPED_NAMES     0x0010
#define RLOG_PID                0x0020

#define RLOG_DEFAULT            (RLOG_AUTH | RLOG_FAILED_PASS)

#define VERBOSE_DEFAULT         1

/* Debug logging levels: */
#define DEBUG_PAIRS             0x00000001 
#define DEBUG_MALLOC            0x00000002 
#define DEBUG_REQUEST           0x00000004 
#define DEBUG_REQLIST           0x00000008     
#define DEBUG_REQERR            0x00000010 
#define DEBUG_TERM              0x00000020 
#define DEBUG_AUTH		0x00000040 
#define DEBUG_LOOKUP		0x00000080 
#define DEBUG_HINTS             0x00000100 
#define DEBUG_HUNTGROUPS        0x00000200 
#define DEBUG_EXEC              0x00000400 
#define DEBUG_MYSQL             0x00000800 
#define DEBUG_PROC              0x00001000 
#define DEBUG_PARSER            0x00002000 
#define DEBUG_NOTIFY            0x00004000 
#define DEBUG_IPPOOL            0x00008000
#define DEBUG_PAM               0x00010000
#define DEBUG_SNMP              0x00020000
#define DEBUG_STAT              0x00040000
#define DEBUG_MEM               0x00080000
#define DEBUG_MISC              0x00100000
 
/* log.c */
extern int debug_flag;
extern int log_mode;

void            initlog(char*);
int		log(/*int, char *, ...*/);
int		dlog(/*int, char *, ...*/);
int             debug_printf(/*char *, ...*/);

#define debug(mode) \
 if (debug_flag & mode) debug_printf

