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

#define CONFIG_FILE "checkrad.conf"

#define MATCH_OFFSET 0
#define MATCH_FIELD  1

typedef struct header_list {
	struct header_list *next;
	char *string;
	int offset;
} HEADER_LIST;

typedef struct match_list {
	struct match_list *next;
	int type;
	int num;
	char *hdr;
	char *value;
} MATCH_LIST;

typedef int (*Check)(char*, int);

char * select_offset(char *str, int off);
char * select_field(char *str, int num);
int compare(char *str);
char * checkrad_xlat(char *str);
Check read_config();
int netfinger(char*, int);
int snmp_check(char*, int);
void set_debug_level(char *);
void set_logfile(char *);

extern int want_header;
extern char *nas_port;
extern char *username;
extern char *session_id;
extern char *nas_type;
extern char *snmp_community;
extern char *snmp_oid;
extern char *snmp_match;

/* temporary kludge */
#define logit radlog
