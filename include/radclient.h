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

#define PORT_AUTH 0
#define PORT_ACCT 1
#define PORT_CNTL 2

typedef struct server {
	struct server *next;
	struct server *next_avail;
	UINT4  addr;
	char   *name;
	int    port[3];
	char   secret[AUTH_PASS_LEN+1];
} SERVER;

typedef struct {
	size_t bufsize;
	char  *data_buffer;
	char   vector[AUTH_VECTOR_LEN];
	int    timeout;
	int    retries;
	int    messg_id;
	SERVER *server;
	SERVER *first_server;
} RADCLIENT;	

RADCLIENT * radclient_init(char *config_dir);
AUTH_REQ *radclient_send(RADCLIENT *config, int port_type,
			 int code, VALUE_PAIR *pair);

SERVER * radclient_find_server(RADCLIENT *config, char *name);
int radclient_delete_server(RADCLIENT *config, char *name);
int radclient_add_server(RADCLIENT *config, char *name);


