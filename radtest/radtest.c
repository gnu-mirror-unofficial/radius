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

static char rcsid[] = 
"$Id$";

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <stdlib.h>
#include <time.h>

#include <radiusd.h>
#include <radclient.h>
#include <radpaths.h>
#include <radtest.h>

#define MAXPWNAM	32
#define MAXPASS		16

#define TEST_VENDOR	0
#define TEST_USR	0

RADCLIENT       *radclient;
char		*progname;
int		sockfd;
int             reply_code;

int		debug_flag = 0;

int
xlat_port(var, port)
	Variable *var;
	int *port;
{
	struct servent *serv;
	
	switch (var->type) {
	case Integer:
		*port = var->datum.number;
		break;
	case String:
		serv = getservbyname(var->datum.string, "udp");
		if (serv == NULL) {
			parse_error(_("unknown service name: %s"), var->datum.string);
			return -1;
		}
		*port = ntohs(serv->s_port);
		break;
	default:
		parse_error(_("bad datatype"));
		return -1;
	}
	return 0;
}

void
radtest_send(port, code, var)
	int port;
	int code;
	Variable *var;
{
	AUTH_REQ *auth;
	
	if (var->type != Vector) {
		parse_error(_("wrong datatype: expected vector"));
		return;
	}

	auth = radclient_send(radclient,
			      port,
			      code, var->datum.vector);
	if (!auth)
		return;

	reply_code = auth->code;
	var = (Variable*)sym_lookup(vartab, "REPLY_CODE");
	var->type = Integer;
	var->datum.number = reply_code;
	var = (Variable*)sym_lookup(vartab, "REPLY");
	var->type = Vector;
	var->datum.vector = NULL;
	var->datum.vector = paircopy(auth->request);
	authfree(auth);
}





