/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define PORT_AUTH 0
#define PORT_ACCT 1
#define PORT_MAX  2

typedef struct server {
        struct server *next;
        UINT4  addr;
        char   *name;
        int    port[PORT_MAX];
        char   *secret;
} SERVER;

typedef struct {
        size_t bufsize;
        char  *data_buffer;
        char   vector[AUTH_VECTOR_LEN];
        UINT4  source_ip;
        unsigned timeout;
        unsigned retries;
        unsigned messg_id;
        SERVER *first_server;
} RADCLIENT;    

RADCLIENT *radclient_alloc(int read_cfg, UINT4 source_ip, size_t bufsize);
RADIUS_REQ *radclient_send(RADCLIENT *config, int port_type,
                         int code, VALUE_PAIR *pair);

SERVER *radclient_alloc_server(SERVER *data);

SERVER *radclient_dup_server(SERVER *src);
void radclient_free_server(SERVER *server);
SERVER *radclient_append_server(SERVER *list, SERVER *server);
void radclient_clear_server_list(SERVER *list);
SERVER *radclient_find_server(SERVER *list, char *name);



