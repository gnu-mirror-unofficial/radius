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

#define RADIUS_MODULE 5
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <log.h>
#include <radiusd.h>
#include <checkrad.h>

static char *source_name = CONFIG_FILE;
static int source_line ;
static char *buffer;
static char *curp;
static struct token {
	int type;
	char string[1024];
} token;
static Check checkfun = NULL;


static void putback(char *tok, int length);
static void skipws();
static void skipline();
static int isword(int c);
static void copy_alpha();
static void copy_string();
static int copy_digit();
static int config_finger_match();
static int config_snmp_match();
static int config_error();

static int (*config_match)() = config_error;

#define T_EOL       '\n'
#define T_TYPE      256
#define T_METHOD    257
#define T_MATCH     258
#define T_HEADER    259
#define T_STRING    260
#define T_NUMBER    261
#define T_COMMUNITY 262
#define T_OID       263
#define T_LOGFILE   264
#define T_DEBUG     265

static struct keyword keyword_list[] = {
	"logfile",   T_LOGFILE,
	"debug",     T_DEBUG,
	"type",      T_TYPE,
	"method",    T_METHOD,
	"match",     T_MATCH,
	"header",    T_HEADER,
	"community", T_COMMUNITY,
	"oid",       T_OID,
	0
};

int
yylex()
{
	int type;

again:
	skipws();

	debug(20,("%s:%d: looking at `%32.32s'",
		  source_name, source_line, curp));
	
	if (*curp == '#') { 
		skipline();
		goto again;
	} 

	if (*curp == 0)
		return 0;
	
	if (*curp == '\"') {
		copy_string();
		return T_STRING;
	}
	
	if (isalpha(*curp)) {
		copy_alpha();
		type = xlat_keyword(keyword_list, token.string, -1);
		if (type < 0)
			type = T_STRING;
		return type;
	}
	
	if (*curp == '$' || *curp == '@' || *curp == '%') {
		type = *curp;
		copy_alpha();
		return type;
	}

	if (isdigit(*curp)) {
		copy_digit();
		return T_NUMBER;
	} 

	if (*curp == '\n')
		source_line++;
	return *curp++;
}

char *
restofline()
{
	char *p;
	int len;

	skipws();
	p = curp;
	curp = strchr(curp, '\n');
	if (!curp) {
		len = sizeof(token.string) - 1;
		curp = buffer + strlen(buffer) - 1;
	} else {
		len = curp - p;
		if (len > sizeof(token.string) - 1)
			len = sizeof(token.string) - 1;
	}
	strncpy(token.string, p, len);
	while (len > 1 && isspace(token.string[len-1]))
		len--;
	token.string[len] = 0;
	debug(10, ("%s:%d: restofline returns %s",
		 source_name, source_line, token.string));
	return token.string;
}

int
nextkn()
{
	token.type = yylex();
	debug(10, ("%s:%d: token (%d) %s", source_name, source_line,
		 token.type, token.string));
	return token.type;
}

void
putback(tok, length)
	char *tok;
	int length;
{
	if (length > curp - buffer) {
		logit(L_CRIT,
		      _("INTERNAL ERROR parsing %s near %d: out of putback space"),
		      source_name, source_line);
		return;
	}	
	while (length--)	
		*--curp = tok[length];		
}

void
skipws()
{
	while (*curp && (*curp == ' ' || *curp == '\t')) 
		curp++;
}

void
skipline()
{
	while (*curp && *curp != '\n')
		curp++;
	if (*curp == '\n') {
		source_line++;
		curp ++;
	}
}

int
isword(c)
	int c;
{
	return isalnum(c) || strchr("_-$@", c);
}

void
copy_alpha()
{
	char * p = token.string;
	
	do {
		if (p >= token.string + sizeof(token.string)) {
			radlog(L_ERR, _("%s:%d: token too long"),
			    source_name, source_line);
			break;
		}
		*p++ = *curp++;
	} while (*curp && isword(*curp));
	*p = 0;
}

void
copy_string()
{
	char * p = token.string;
	int quote = *curp++;

	while (*curp) {
		if (*curp == quote) {
			curp++;
			break;
		}
		if (p >= token.string + sizeof(token.string)) {
			logit(L_ERR, _("%s:%d: token too long"),
			      source_name, source_line);
			break;
		}
		*p++ = *curp++;
	} 
	*p = 0;
}

int
copy_digit()
{
	char *p = token.string;

	if (*curp == '0') {
		if (curp[1] == 'x' || curp[1] == 'X') {
			*p++ = *curp++;
			*p++ = *curp++;
		}
	}
	
	do {
		if (p >= token.string + sizeof(token.string)) {
			logit(L_ERR, _("%s:%d: token too long"),
			      source_name, source_line);
			break;
		}
		*p++ = *curp++;
	} while (*curp && isdigit(*curp));
	*p = 0;
	return 0;
}



Check
read_config()
{
	int fd;
	int type_found = 0;
	struct stat st;

	source_name = mkfilename(radius_dir, CONFIG_FILE);
	if (stat(source_name, &st)) {
		logit(L_ERR|L_PERROR, _("can't stat `%s'"), source_name);
		return;
	}
	fd = open(source_name, O_RDONLY);
	if (fd == -1) {
		logit(L_ERR|L_PERROR,
		      _("can't open config file `%s'"), source_name);
		return NULL;
	}
	buffer = emalloc(st.st_size+1);
	if (!buffer) {
		logit(L_ERR,
		      _("not enough memory to read config file `%s'"),
		      source_name);
		close(fd);
		return NULL;
	}
	read(fd, buffer, st.st_size);
	buffer[st.st_size] = 0;
	close(fd);
	curp = buffer;
	source_line = 1;
	
	while (nextkn()) {
		switch (token.type) {
		case T_EOL:
			continue;
		case T_LOGFILE:
			set_logfile(restofline());
			continue;
		case T_DEBUG:
			set_debug_levels(restofline());
			continue;
		}
		if (type_found) {
			switch (token.type) {
			case T_TYPE:
				return checkfun;
			case T_METHOD:
				config_method();
				break;
			case T_HEADER:
				config_header();
				break;
			case T_MATCH:
				config_match();
				break;
			case T_COMMUNITY:
				config_community();
				break;
			case T_OID:
				config_oid();
				break;
			default:
				logit(L_ERR, _("%s:%d: syntax error"),
				      source_name, source_line);
				exit(-1);
			}
			if (token.type && token.type != T_EOL) {
				logit(L_WARN, _("%s:%d: junk at end of line: %s"),
				      source_name, source_line, curp);
				skipline();
			}
		} else {
			if (token.type == T_TYPE) {
				nextkn();
				if (strcmp(token.string, nas_type) == 0)
					type_found++;
			}
			if (!type_found)
				skipline();
		}
	}
	return checkfun;
}

int
config_method()
{
	nextkn();

	if (strcmp(token.string, "finger") == 0) {
		debug(5,("%s:%d: matched method finger",
			 source_name, source_line));
		checkfun = netfinger;
		config_match = config_finger_match;
		nextkn();
	} else if (strcmp(token.string, "snmp") == 0) {
		debug(5,("%s:%d: matched method snmp",
			 source_name, source_line));
		checkfun = snmp_check;
		config_match = config_snmp_match;
		nextkn();
	} else {
		logit(L_ERR, _("%s:%d: unknown method: %s"),
		      source_name, source_line,
		      token.string);
		exit(-1);
	}
}

int
config_header()
{
	char *str, *s;
	int delim;
	
	nextkn();

	want_header = atoi(token.string);
	str = restofline();
	nextkn();
	
	if (ispunct(*str)) 
		delim = *str++;
	else
		delim = ':';
	while (str && *str) {
		s = strchr(str, delim);
		if (s)
			*s++ = 0;
		add_header(str);
		str = s;
	}
}

int
config_finger_match()
{
	MATCH_LIST match;

	do {
		bzero(&match, sizeof(match));
		nextkn();
		if (token.string[0] == '$') {
			/* Field spec */
			match.type = MATCH_FIELD;
			match.num = atoi(token.string+1);
		} else if (token.string[0] == '@') {
			/* Offset spec */
			match.type = MATCH_FIELD;
			match.num = atoi(token.string+1);
		} else {
			/* Header spec */
			match.type = MATCH_OFFSET;
			match.hdr = estrdup(token.string);
		}

		nextkn();
		if (token.type != '=') {
			logit(L_ERR, _("%s:%d: expected '=' but found %s"),
			      source_name, source_line,
			      token.string);
			exit(-1);
		}
		nextkn();
		match.value = estrdup(token.string);

		add_match(&match);

		nextkn();
	} while (token.type == ',');
	
}

int
config_snmp_match()
{
	snmp_match = checkrad_xlat(restofline());
	debug(5,("%s:%d: snmp_match = %s",
		 source_name, source_line, snmp_match));
	nextkn();
}

int
config_community()
{
	nextkn();
	snmp_community = estrdup(token.string);
	debug(5,("%s:%d: snmp_community = %s",
		 source_name, source_line, snmp_community));
	nextkn();
}

int
config_oid()
{
	snmp_oid = checkrad_xlat(restofline());
	debug(5,("%s:%d: snmp_oid = %s",
		 source_name, source_line, snmp_oid));
	nextkn();
}
		
int
config_error()
{
	logit(L_ERR, _("%s:%d: shouldn't happen: don't know how to handle match here"),
	      source_name, source_line);
}
