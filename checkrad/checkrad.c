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
/* Checks if the user has already logged in to the given NAS
 * usage: checkrad nas_type nas_ip nas_port login session_id
 * Return value:
 *        0    the user is not logged in
 *        1    the user is logged in
 *        <0   error (== I don't know)
 */
#define RADIUS_MODULE 2

static char rcsid[] = "$Id$";

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include <sysdep.h>
#include <radiusd.h>
#include <mem.h>
#include <obstack1.h>
#include <log.h>
#include <checkrad.h>

char *nas_type = NULL;
char *nas_port = NULL;
char *username = NULL;
char *session_id = NULL;
char *snmp_community = NULL;
char *snmp_oid = NULL;
char *snmp_match = NULL;
struct obstack stk;

/* Sorry, this is the only non-configurable define.
 * The reason it is still there is that I plan to get rid of calling
 * snmpget in the next release.
 */
#define SNMPGET "/usr/local/bin/snmpget"

int
main(argc, argv)
	int argc;
	char **argv;
{
 	struct check_list *cp;
	int c;
	char *host = NULL;
	Check checkfun = NULL;
	int port = 0;
	
	obstack_init(&stk);
	initlog(argv[0]);
	
	while ((c = getopt(argc, argv, "d:h:p:t:u:s:x:")) != EOF) {
		switch (c) {
		case 'd':
			radius_dir = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			nas_port = optarg;
			if (nas_port[0] == 's' || nas_port[0] == 'S')
				nas_port++;
			break;
		case 't':
			nas_type = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 's':
			session_id = optarg;
			break;
		case 'x':
			set_debug_levels(optarg);
			break;
		default:
			logit(L_ERR, _("bad argument"));
		}
	}

	radpath_init();
	
	if (!nas_type || !host || !nas_port || !username || !session_id) {
		printf(_("usage: checkrad [-h host][-p nas_port][-t type][-u user][-s session_id]\n"));
		return -1;
	}

	checkfun = read_config();
	
	debug(1, ("started: host %s, type %s, user %s, port %s, sid %s",
		   host, nas_type, username, nas_port, session_id));

	if (checkfun)
		return checkfun(host, port);

	logit(L_ERR, _("unknown NAS type: %s"), nas_type);
	return -1; /* unknown type */
}

/* Replace: %u  -- username
 *          %s  -- session id
 *          %p  -- port no
 *          %P  -- port no + 1
 */
char *
checkrad_xlat(str)
	char *str;
{
	char *ptr;
	int len;
	char buf[24];
	
	while (*str) {
		if (*str == '%') {
			switch (str[1]) {
			case 'u':
				ptr = username;
				break;
			case 's':
				ptr = session_id;
				break;
			case 'd':
				sprintf(buf, "%d", strtol(session_id, NULL, 16));
				ptr = buf;
				break;
			case 'p':
				ptr = nas_port;
				break;
			case 'P':
				sprintf(buf, "%d", atoi(nas_port) + 1);
				ptr = buf;
				break;
			default:
				ptr = NULL;
				obstack_grow(&stk, str, 2);
			}
			if (ptr) {
				len = strlen(ptr);
				obstack_grow(&stk, ptr, len);
			}
			str += 2;
		} else {
			obstack_1grow(&stk, *str);
			str++;
		}
	}
	obstack_1grow(&stk, 0);
	return obstack_finish(&stk);
}

/* ********* Compatibility stuff **************** */

int
snmp_check(nas_ip, port_unused)
	char *nas_ip;
	int port_unused;
{
	int port;
	char *ptr;
	char buffer[1024];
	FILE *fp;

	if (!snmp_community) {
		logit(L_ERR, _("no snmp_community"));
		return -1;
	}
	if (!snmp_oid) {
		logit(L_ERR, _("no snmp_oid"));
		return -1;
	}
	if (!snmp_match) {
		logit(L_ERR, _("no snmp_match"));
		return -1;
	}

	sprintf(buffer, "%s %s %s %s",
		SNMPGET,
		nas_ip,
		snmp_community,
		snmp_oid);

	debug(3, ("SNMP: calling %s", buffer));
	
	fp = popen(buffer, "r");
	if (!fp) {
 		logit(L_ERR|L_PERROR, _("can't run %s"), SNMPGET);
		return -1;
	}
	ptr = fgets(buffer, sizeof(buffer), fp);
	pclose(fp);

	if (!ptr) {
		logit(L_ERR, _("No response from %s"), SNMPGET);
		return -1;
	}
	debug(3,("got %s", ptr));

	/* Skip variable name */
	while (*ptr && *ptr != '=')
		ptr++;

	if (!*ptr)
		return -1;
	
	/* skip spaces */
	++ptr;
	while (*ptr && isspace(*ptr))
		++ptr;
	
	if (!*ptr)
		return -1;

	if (*ptr == '\"') {
		int len;
		
		++ptr;
		len = strlen(ptr);
		if (len) {
			if (ptr[len-1] == '\n')
				ptr[--len] = 0;
			if (ptr[len-1] == '\"')
				ptr[len-1] = 0;
		}
	}
	return strncmp(snmp_match, ptr, sizeof(snmp_match)) == 0;
}

