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

#define RADIUS_MODULE_CLIENT_C
#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <radius.h>
#include <slist.h>
#include <debugmod.h>

void
rad_clt_random_vector(vector)
        char *vector;
{
        int randno;
        int i;

        for (i = 0; i < AUTH_VECTOR_LEN; ) {
                randno = rand();
                memcpy(vector, &randno, sizeof(int));
                vector += sizeof(int);
                i += sizeof(int);
        }
}

RADIUS_REQ *
rad_clt_recv(host, udp_port, secret, vector, buffer, length)
        UINT4 host;
        u_short udp_port;
        char *secret;
        char *vector;
        char *buffer;
        int length;
{
        AUTH_HDR *auth;
        int totallen;
        u_char reply_digest[AUTH_VECTOR_LEN];
        u_char calc_digest[AUTH_VECTOR_LEN];
        int  secretlen;

        auth = (AUTH_HDR *)buffer;
        totallen = ntohs(auth->length);

        if (totallen != length) {
                radlog(L_ERR,
           _("Actual request length does not match reported length (%d, %d)"),
                       totallen, length);
                return NULL;
        }

        /* Verify the reply digest */
        secretlen = strlen(secret);
        memcpy(reply_digest, auth->vector, AUTH_VECTOR_LEN);
        memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
        memcpy(buffer + length, secret, secretlen);
        md5_calc(calc_digest, (unsigned char *)auth, length + secretlen);
        
	debug(1, ("received %s", auth_code_str(auth->code)));
        if (memcmp(reply_digest, calc_digest, AUTH_VECTOR_LEN) != 0) {
                radlog(L_WARN, _("Received invalid reply digest from server"));
        }

        return rad_decode_pdu(host, udp_port, buffer, length);
}

static VALUE_PAIR *
_encode_pairlist(p, vector, secret)
	VALUE_PAIR *p;
	u_char *vector;
	u_char *secret;
{
	VALUE_PAIR *ret = avl_dup(p);

	for (p = ret; p; p = p->next)
		if (p->attribute == DA_USER_PASSWORD
		    || p->attribute == DA_CHAP_PASSWORD) {
			char *pass = p->avp_strvalue;
			encrypt_password(p, pass, vector, secret);
			string_free(pass);
		}
	return ret;
}


RADIUS_REQ *
rad_clt_send(config, port_type, code, pairlist)
        RADIUS_SERVER_QUEUE *config;
        int port_type;
        int code;
        VALUE_PAIR *pairlist;
{
	struct sockaddr salocal;
	struct sockaddr saremote;
	struct sockaddr_in *sin;
        int local_port;
        int sockfd;
        int salen;
        int i;
        RADIUS_REQ *req = NULL;
        RADIUS_SERVER *server;
        char ipbuf[DOTTED_QUAD_LEN];
	char *recv_buf;
	
        if (port_type < 0 || port_type > 2) {
                radlog(L_ERR, _("invalid port type"));
                return NULL;
        }
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
                radlog(L_ERR|L_PERROR, "socket");
                return NULL;
        }

        sin = (struct sockaddr_in *) &salocal;
        memset (sin, 0, sizeof (salocal));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = config->source_ip ?
                                   htonl(config->source_ip) : INADDR_ANY;

	/*FIXME: not necessary?*/
        local_port = 1025;
        do {
                local_port++;
                sin->sin_port = htons((u_short)local_port);
        } while ((bind(sockfd, &salocal, sizeof (struct sockaddr_in)) < 0)
		 && local_port < 65535);
        if (local_port >= 65535) {
                radlog(L_ERR|L_PERROR, "bind");
                close(sockfd);
                return NULL;
        }

	debug(1,
	      ("sending %s", auth_code_str(code)));
	recv_buf = emalloc(config->buffer_size);
        server = config->first_server;
        do {
		fd_set readfds;
		struct timeval tm;
		int result;
		u_char vector[AUTH_VECTOR_LEN];
		void *pdu;
		size_t size;
		VALUE_PAIR *pair;
		
                if (server->port[port_type] <= 0)
                        continue;
                
                if (debug_on(10)) {
                        radlog(L_DEBUG, "server %s:%d",
                               ip_iptostr(server->addr, ipbuf),
                               server->port[port_type]);
                }
                
		rad_clt_random_vector(vector);
		pair = _encode_pairlist(pairlist, vector, server->secret);
		size = rad_create_pdu(&pdu, code,
				      config->messg_id,
				      vector,
				      server->secret,
				      pair,
				      NULL);

		avl_free(pair);
		
                if (size <= 0) 
                        break; /*FIXME: continue anyway?*/
        
                /* Now send the request. */
                
                sin = (struct sockaddr_in *) &saremote;
                memset(sin, 0, sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(server->addr);
                sin->sin_port = htons(server->port[port_type]);

                for (i = 0; i < config->retries; i++) {
                        if (sendto(sockfd, pdu, size, 0,
                                   &saremote,
                                   sizeof(struct sockaddr_in)) == -1) {
                                radlog(L_ERR|L_PERROR, "sendto");
                        }

                        salen = sizeof (saremote);

                        tm.tv_usec = 0L;
                        tm.tv_sec = (long) config->timeout;
                        FD_ZERO(&readfds);
                        FD_SET(sockfd, &readfds);
                        if (select(sockfd+1, &readfds, NULL, NULL, &tm) < 0) {
                                if (errno == EINTR) {
                                        i--;
					debug(20,
					      ("select interrupted. retrying."));
                                        continue;
                                }
                                radlog(L_NOTICE, _("select() interrupted"));
                                break;
                        }

                        if (FD_ISSET (sockfd, &readfds)) {
                                result = recvfrom(sockfd,
                                                  recv_buf,
                                                  config->buffer_size,
                                                  0, &saremote, &salen);

                                if (result > 0) 
                                        req = rad_clt_recv(
						sin->sin_addr.s_addr,
                                                sin->sin_port,
                                                server->secret,
                                                vector,
                                                recv_buf,
                                                result);
                                else 
                                        radlog(L_ERR|L_PERROR,
                                        _("error receiving data from %s:%d"),
                                               ip_iptostr(server->addr, ipbuf),
                                               server->port[port_type]);
                                
                                break;
                        }
			debug(10,("no response. retrying."));
                }
		
		efree(pdu);
		
                if (!req)
                        debug(10,("no reply from %s:%d",
				  ip_iptostr(server->addr, ipbuf),
				  server->port[port_type]));
		
        } while (!req && (server = server->next) != NULL);

	efree(recv_buf);
        close(sockfd);
        return req;
}

/* ************************************************************************* */
/* Initialization. */

#define TOK_INVALID    0
#define TOK_SOURCE_IP  1
#define TOK_SERVER     2
#define TOK_TIMEOUT    3
#define TOK_RETRY      4

static struct keyword kwd[] = {
        "source_ip", TOK_SOURCE_IP,
        "source-ip", TOK_SOURCE_IP,
        "server", TOK_SERVER,
        "timeout", TOK_TIMEOUT,
        "retry", TOK_RETRY,
        NULL
};

static int
parse_client_config(client, argc, argv, file, lineno)
        RADIUS_SERVER_QUEUE *client;
        int argc;
        char **argv;
        char *file;
        int lineno;
{
        char *p;
        RADIUS_SERVER serv;
        
        switch (xlat_keyword(kwd, argv[0], TOK_INVALID)) {
        case TOK_INVALID:
                radlog(L_ERR, "%s:%d: unknown keyword", file, lineno);
                break;
                
        case TOK_SOURCE_IP:
                client->source_ip = ip_gethostaddr(argv[1]);
                break;
                
        case TOK_SERVER:
                if (argc != 6) {
                        radlog(L_ERR, "%s:%d: wrong number of fields",
                               file, lineno);
                        break;
                }
                memset(&serv, 0, sizeof serv);

                serv.name = argv[1];
                serv.addr = ip_gethostaddr(argv[2]);
                if (!serv.addr) {
                        radlog(L_ERR,
                               "%s:%d: bad IP address or host name",
                               file, lineno);
                        break;
                }
                
                serv.secret = argv[3];

                serv.port[0] = strtol(argv[4], &p, 0);
                if (*p) {
                        radlog(L_ERR,
                               "%s:%d: bad port number %s",
                               file, lineno, argv[4]);
                        break;
                }

                serv.port[1] = strtol(argv[5], &p, 0);
                if (*p) {
                        radlog(L_ERR,
                               "%s:%d: bad port number %s",
                               file, lineno, argv[4]);
                        break;
                }
                
                client->first_server =
                        rad_clt_append_server(client->first_server,
                                                rad_clt_alloc_server(&serv));
                break;
                
        case TOK_TIMEOUT:
                client->timeout = strtol(argv[1], &p, 0);
                if (*p) {
                        radlog(L_ERR,
                               "%s:%d: bad timeout value", file, lineno);
                }
                break;
                
        case TOK_RETRY:
                client->retries = strtol(argv[1], &p, 0);
                if (*p) {
                        radlog(L_ERR,
                               "%s:%d: bad retry value", file, lineno);
                }
                break;
        }
        return 0;
}


RADIUS_SERVER_QUEUE *
rad_clt_create_queue(read_cfg, source_ip, bufsize)
        int read_cfg;
        UINT4 source_ip;
        size_t bufsize;
{
        RADIUS_SERVER_QUEUE *client;
        struct timeval tv;
        char *filename;
        
        client = emalloc(sizeof *client);

        /* Provide default values */
        client->source_ip = source_ip;
        client->timeout = 1;
        client->retries = 3;
        client->buffer_size = bufsize ? bufsize : 4096;
        client->first_server = NULL;

        gettimeofday(&tv, NULL);
        srand(tv.tv_usec);
        client->messg_id = random() % 256;

        if (read_cfg) {
                filename = mkfilename(radius_dir, "client.conf");
                read_raddb_file(filename, 1, parse_client_config, client);
                efree(filename);
        }
        return client;
}

void
rad_clt_destroy_queue(queue)
        RADIUS_SERVER_QUEUE *queue;
{
	if (queue) {
		rad_clt_clear_server_list(queue->first_server);
		efree(queue);
	}
}

RADIUS_SERVER *
rad_clt_alloc_server(src)
        RADIUS_SERVER *src;
{
        RADIUS_SERVER *server;

        server = mem_alloc(sizeof(*server));
        server->name = string_create(src->name);
        server->addr = src->addr;
        server->port[0] = src->port[0];
        server->port[1] = src->port[1];
        server->secret = string_create(src->secret);
        return server;
}

RADIUS_SERVER *
rad_clt_dup_server(src)
        RADIUS_SERVER *src;
{
        RADIUS_SERVER *dest;

        dest = mem_alloc(sizeof(*dest));
        dest->addr = src->addr;
        dest->name = string_dup(src->name);
        dest->port[0] = src->port[0];
        dest->port[1] = src->port[1];
        dest->secret = string_dup(src->secret);
        return dest;
}

/* ************************************************************************* */
/* Functions to manipulate server lists
 */

void
rad_clt_free_server(server)
        RADIUS_SERVER *server;
{
        string_free(server->name);
        string_free(server->secret);
        mem_free(server);
}

RADIUS_SERVER *
rad_clt_append_server(list, server)
        RADIUS_SERVER *list;
        RADIUS_SERVER *server;
{
        return (RADIUS_SERVER*)append_slist((struct slist*)list,
                                     (struct slist*)server);
}

static void
rad_clt_internal_free_server(server)
        RADIUS_SERVER *server;
{
        string_free(server->name);
        string_free(server->secret);
}

void
rad_clt_clear_server_list(list)
        RADIUS_SERVER *list;
{
        free_slist((struct slist *)list, rad_clt_internal_free_server);
}

static int
server_cmp(serv, id)
        RADIUS_SERVER *serv;
        char *id;
{
        return strcmp(serv->name, id);
}

RADIUS_SERVER *
rad_clt_find_server(list, name)
        RADIUS_SERVER *list;
        char *name;
{
        return (RADIUS_SERVER*)find_slist((struct slist *)list,
                                   server_cmp,
                                   name);
}

