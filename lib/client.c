/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
 
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_CLIENT_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <radius.h>
#include <debugmod.h>

void
grad_client_random_vector(char *vector)
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

#define PERM S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP

unsigned
grad_client_message_id(RADIUS_SERVER *server)
{
	SERVER_ID sid;
	int fd;
	unsigned id;
	
	fd = open(radmsgid_path, O_RDWR|O_CREAT, PERM);
	if (fd != -1) {
		struct stat st;
		
		fstat(fd, &st);
		if (server->id_offset != (off_t) -1
		    && server->id_offset + sizeof(sid) <= st.st_size) {
			grad_lock_file(fd, sizeof(sid), server->id_offset, SEEK_SET);
			lseek(fd, server->id_offset, SEEK_SET);
			read(fd, &sid, sizeof(sid));
			id = sid.id++;
			lseek(fd, server->id_offset, SEEK_SET);
			write(fd, &sid, sizeof(sid));
			grad_unlock_file(fd, sizeof(sid),
				   server->id_offset, SEEK_SET);

		} else {
			off_t off = 0;
			lseek(fd, 0, SEEK_SET);
			grad_lock_file(fd, st.st_size + sizeof(sid), 0, SEEK_SET);
			while (read(fd, &sid, sizeof(sid)) == sizeof(sid)) {
				if (sid.addr == server->addr) {
					id = sid.id++;
					lseek(fd, off, SEEK_SET);
					write(fd, &sid, sizeof(sid));
					break;
				}
				off += sizeof(sid);
			}
			if (off == st.st_size) {
				/* Entry not found. */
				sid.addr = server->addr;
				sid.id = 1;
				write(fd, &sid, sizeof(sid));
				server->id_offset = off;
				id = 0;
			} 
			grad_unlock_file(fd, st.st_size + sizeof(sid), 0, SEEK_SET);
		}
		close(fd);
	} else {
		id = random() % 256;
	}
	return id;
}
	
RADIUS_REQ *
grad_client_recv(UINT4 host, u_short udp_port, char *secret, char *vector,
	     char *buffer, int length)
{
        AUTH_HDR *auth;
        int totallen;
        u_char reply_digest[AUTH_VECTOR_LEN];
        u_char calc_digest[AUTH_VECTOR_LEN];
        int  secretlen;
	RADIUS_REQ *req;
	
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

        req = grad_decode_pdu(host, udp_port, buffer, length);
	req->secret = secret;
		
	return req;
}

VALUE_PAIR *
grad_client_encrypt_pairlist(VALUE_PAIR *plist, u_char *vector, u_char *secret)
{
	VALUE_PAIR *p;
	
	for (p = plist; p; p = p->next) {
		if (p->prop & AP_ENCRYPT_RFC2138) {
			char *pass = p->avp_strvalue;
			grad_encrypt_password(p, pass, vector, secret);
			efree(pass);
		} else if (p->prop & AP_ENCRYPT_RFC2868) {
			char *pass = p->avp_strvalue;
			grad_encrypt_tunnel_password(p, 0, pass, vector, secret);
			efree(pass);
		}
	}
	return plist;
}	

VALUE_PAIR *
grad_client_decrypt_pairlist(VALUE_PAIR *plist, u_char *vector, u_char *secret)
{
	VALUE_PAIR *p;
	char password[AUTH_STRING_LEN+1];
	
	for (p = plist; p; p = p->next) {
		if (p->prop & AP_ENCRYPT_RFC2138) {
			grad_decrypt_password(password, p, vector, secret);
			efree(p->avp_strvalue);
			p->avp_strvalue = estrdup(password);
			p->avp_strlength = strlen(p->avp_strvalue);
		} else if (p->prop & AP_ENCRYPT_RFC2868) {
			u_char tag;
			
			grad_decrypt_tunnel_password(password,
						&tag,
						p,
						vector,
						secret);
			efree(p->avp_strvalue);
			p->avp_strvalue = estrdup(password);
			p->avp_strlength = strlen(p->avp_strvalue);
		}
	}
	return plist;
}

RADIUS_REQ *
grad_client_send0(RADIUS_SERVER_QUEUE *config, int port_type, int code,
	      VALUE_PAIR *pairlist,
	      int flags,
	      int *authid, u_char *authvec)
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
	ITERATOR *itr;
	int id;
	
        if (port_type < 0 || port_type > 2) {
                radlog(L_ERR, _("invalid port type"));
                return NULL;
        }
        sockfd = socket(PF_INET, SOCK_DGRAM, 0);
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
        itr = iterator_create(config->servers);
        server = iterator_first(itr);
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
                               grad_ip_iptostr(server->addr, ipbuf),
                               server->port[port_type]);
                }

                if (authid && (flags & RADCLT_AUTHENTICATOR))
			memcpy(vector, authvec, sizeof vector);
		else
			grad_client_random_vector(vector);
		if (authid && (flags & RADCLT_ID))
			id = *authid;
		else
			id = grad_client_message_id(server);
		pair = grad_client_encrypt_pairlist(grad_avl_dup(pairlist),
						vector, server->secret);
		size = grad_create_pdu(&pdu, code,
				      id,
				      vector,
				      server->secret,
				      pair,
				      NULL);
		if (authid && !(flags & RADCLT_ID))
			*authid = id;
		if (authvec && !(flags & RADCLT_AUTHENTICATOR))
			memcpy(authvec, vector, sizeof vector);
		
		grad_avl_free(pair);
		
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
                                        req = grad_client_recv(
						sin->sin_addr.s_addr,
                                                sin->sin_port,
                                                server->secret,
                                                vector,
                                                recv_buf,
                                                result);
                                else 
                                        radlog(L_ERR|L_PERROR,
                                        _("error receiving data from %s:%d"),
                                               grad_ip_iptostr(server->addr, ipbuf),
                                               server->port[port_type]);
                                
                                break;
                        }
			debug(10,("no response. retrying."));
                }
		
		efree(pdu);
		
                if (!req)
                        debug(10,("no reply from %s:%d",
				  grad_ip_iptostr(server->addr, ipbuf),
				  server->port[port_type]));
		
        } while (!req && (server = iterator_next(itr)) != NULL);
	iterator_destroy(&itr);

	efree(recv_buf);
        close(sockfd);
        return req;
}

RADIUS_REQ *
grad_client_send(RADIUS_SERVER_QUEUE *config, int port_type, int code,
	     VALUE_PAIR *pairlist)
{
	return grad_client_send0(config, port_type, code, pairlist, 0, NULL, NULL);
}

/* ************************************************************************* */
/* Initialization. */

#define TOK_INVALID    0
#define TOK_SOURCE_IP  1
#define TOK_SERVER     2
#define TOK_TIMEOUT    3
#define TOK_RETRY      4

static struct keyword kwd[] = {
        { "source_ip", TOK_SOURCE_IP },
        { "source-ip", TOK_SOURCE_IP },
        { "server", TOK_SERVER },
        { "timeout", TOK_TIMEOUT },
        { "retry", TOK_RETRY },
        { NULL }
};

static int
parse_client_config(void *closure, int argc, char **argv, LOCUS *loc)
{
	RADIUS_SERVER_QUEUE *client = closure;
        char *p;
        RADIUS_SERVER serv;
        
        switch (grad_xlat_keyword(kwd, argv[0], TOK_INVALID)) {
        case TOK_INVALID:
                radlog_loc(L_ERR, loc, _("unknown keyword"));
                break;
                
        case TOK_SOURCE_IP:
                client->source_ip = grad_ip_gethostaddr(argv[1]);
                break;
                
        case TOK_SERVER:
                if (argc != 6) {
                        radlog_loc(L_ERR, loc, _("wrong number of fields"));
                        break;
                }
                memset(&serv, 0, sizeof serv);

                serv.name = argv[1];
                serv.addr = grad_ip_gethostaddr(argv[2]);
                if (!serv.addr) {
                        radlog_loc(L_ERR, loc,
				   _("bad IP address or host name"));
                        break;
                }
                
                serv.secret = argv[3];

                serv.port[0] = strtol(argv[4], &p, 0);
                if (*p) {
                        radlog_loc(L_ERR, loc, _("bad port number %s"),
				   argv[4]);
                        break;
                }

                serv.port[1] = strtol(argv[5], &p, 0);
                if (*p) {
                        radlog_loc(L_ERR, loc, _("bad port number %s"),
				   argv[4]);
                        break;
                }

		grad_client_append_server(client, grad_client_alloc_server(&serv));
                break;
                
        case TOK_TIMEOUT:
                client->timeout = strtol(argv[1], &p, 0);
                if (*p) 
                        radlog_loc(L_ERR, loc,  _("bad timeout value"));
                break;
                
        case TOK_RETRY:
                client->retries = strtol(argv[1], &p, 0);
                if (*p) 
                        radlog_loc(L_ERR, loc, _("bad retry value"));
                break;
        }
        return 0;
}


RADIUS_SERVER_QUEUE *
grad_client_create_queue(int read_cfg, UINT4 source_ip, size_t bufsize)
{
        RADIUS_SERVER_QUEUE *client;
        char *filename;
        
        client = emalloc(sizeof *client);

        /* Provide default values */
        client->source_ip = source_ip;
        client->timeout = 1;
        client->retries = 3;
        client->buffer_size = bufsize ? bufsize : 4096;
        client->servers = 0;

        if (read_cfg) {
                filename = grad_mkfilename(radius_dir, "client.conf");
                grad_read_raddb_file(filename, 1, parse_client_config, client);
                efree(filename);
        }
        return client;
}

void
grad_client_destroy_queue(RADIUS_SERVER_QUEUE *queue)
{
	if (queue) {
		grad_client_clear_server_list(queue);
		efree(queue);
	}
}

RADIUS_SERVER *
grad_client_alloc_server(RADIUS_SERVER *src)
{
        RADIUS_SERVER *server;

        server = emalloc(sizeof(*server));
        server->name = estrdup(src->name);
        server->addr = src->addr;
        server->port[0] = src->port[0];
        server->port[1] = src->port[1];
        server->secret = estrdup(src->secret);
	server->id_offset = (off_t)-1;
        return server;
}

RADIUS_SERVER *
grad_client_dup_server(RADIUS_SERVER *src)
{
        RADIUS_SERVER *dest;

        dest = emalloc(sizeof(*dest));
        dest->addr = src->addr;
        dest->name = estrdup(src->name);
        dest->port[0] = src->port[0];
        dest->port[1] = src->port[1];
        dest->secret = estrdup(src->secret);
        return dest;
}

/* ************************************************************************* */
/* Functions to manipulate server lists
 */

void
grad_client_free_server(RADIUS_SERVER *server)
{
        efree(server->name);
        efree(server->secret);
        efree(server);
}

void
grad_client_append_server(RADIUS_SERVER_QUEUE *qp, RADIUS_SERVER *server)
{
	if (!qp->servers)
		qp->servers = grad_list_create();
	grad_list_append(qp->servers, server);
}

static int
grad_client_internal_free_server(void *item, void *data)
{
	RADIUS_SERVER *server = item;
        efree(server->name);
        efree(server->secret);
	efree(server);
	return 0;
}

void
grad_client_clear_server_list(RADIUS_SERVER_QUEUE *qp)
{
	grad_list_destroy(&qp->servers, grad_client_internal_free_server, NULL);
}

static int
server_cmp(const void *item, const void *data)
{
	const RADIUS_SERVER *serv = item;
	const char *id = data;

        return strcmp(serv->name, id);
}

RADIUS_SERVER *
grad_client_find_server(RADIUS_SERVER_QUEUE *qp, char *name)
{
	return grad_list_locate(qp->servers, name, server_cmp);
}

