/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2006,2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
 
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

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

#include <radlib.h>

void
grad_client_random_authenticator(char *authenticator)
{
        int randno;
        int i;

        for (i = 0; i < GRAD_AUTHENTICATOR_LENGTH; ) {
                randno = rand();
                memcpy(authenticator, &randno, sizeof(int));
                authenticator += sizeof(int);
                i += sizeof(int);
        }
}

#define PERM S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP

unsigned
grad_client_message_id(grad_server_t *server)
{
	grad_server_id_t sid;
	int fd;
	unsigned id;
	
	fd = open(grad_msgid_file, O_RDWR|O_CREAT, PERM);
	if (fd != -1) {
		struct stat st;
		
		fstat(fd, &st);
		if (server->id_offset != (off_t) -1
		    && server->id_offset + sizeof(sid) <= st.st_size) {
			grad_lock_file(fd, sizeof(sid),
				       server->id_offset, SEEK_SET);
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
			grad_lock_file(fd, st.st_size + sizeof(sid),
				       0, SEEK_SET);
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
			grad_unlock_file(fd, st.st_size + sizeof(sid),
					 0, SEEK_SET);
		}
		close(fd);
	} else {
		id = random() % 256;
	}
	return id;
}
	
grad_request_t *
grad_client_recv(grad_uint32_t host, u_short udp_port, char *secret,
		 char *authenticator, char *buffer, int length)
{
        grad_packet_header_t *auth;
        int totallen;
        u_char reply_digest[GRAD_AUTHENTICATOR_LENGTH];
        u_char calc_digest[GRAD_AUTHENTICATOR_LENGTH];
        int  secretlen;
	grad_request_t *req;
	
        auth = (grad_packet_header_t *)buffer;
        totallen = ntohs(auth->length);

        if (totallen != length) {
                grad_log(GRAD_LOG_ERR,
           _("Actual request length does not match reported length (%d, %d)"),
                         totallen, length);
                return NULL;
        }

        /* Verify the reply digest */
        secretlen = strlen(secret);
        memcpy(reply_digest, auth->authenticator, GRAD_AUTHENTICATOR_LENGTH);
        memcpy(auth->authenticator, authenticator, GRAD_AUTHENTICATOR_LENGTH);
        memcpy(buffer + length, secret, secretlen);
        grad_md5_calc(calc_digest, (unsigned char *)auth, length + secretlen);
        
	GRAD_DEBUG1(1, "received %s", grad_request_code_to_name(auth->code));
        if (memcmp(reply_digest, calc_digest, GRAD_AUTHENTICATOR_LENGTH) != 0) {
                grad_log(GRAD_LOG_WARN, _("Received invalid reply digest from server"));
        }

        req = grad_decode_pdu(host, udp_port, buffer, length);
	req->secret = secret;
		
	return req;
}

grad_avp_t *
grad_client_encrypt_pairlist(grad_avp_t *plist, u_char *authenticator, u_char *secret)
{
	grad_avp_t *p;
	
	for (p = plist; p; p = p->next) {
		if (p->prop & GRAD_AP_ENCRYPT_RFC2138) {
			char *pass = p->avp_strvalue;
			grad_encrypt_password(p, pass, authenticator, secret);
			grad_free(pass);
		} else if (p->prop & GRAD_AP_ENCRYPT_RFC2868) {
			char *pass = p->avp_strvalue;
			grad_encrypt_tunnel_password(p, 0, pass,
						     authenticator, secret);
			grad_free(pass);
		}
	}
	return plist;
}	

grad_avp_t *
grad_client_decrypt_pairlist(grad_avp_t *plist, u_char *authenticator, u_char *secret)
{
	grad_avp_t *p;
	char password[GRAD_STRING_LENGTH+1];
	
	for (p = plist; p; p = p->next) {
		if (p->prop & GRAD_AP_ENCRYPT_RFC2138) {
			grad_decrypt_password(password, p, authenticator, secret);
			grad_free(p->avp_strvalue);
			p->avp_strvalue = grad_estrdup(password);
			p->avp_strlength = strlen(p->avp_strvalue);
		} else if (p->prop & GRAD_AP_ENCRYPT_RFC2868) {
			u_char tag;
			
			grad_decrypt_tunnel_password(password,
						     &tag,
						     p,
						     authenticator,
						     secret);
			grad_free(p->avp_strvalue);
			p->avp_strvalue = grad_estrdup(password);
			p->avp_strlength = strlen(p->avp_strvalue);
		}
	}
	return plist;
}

static int
wait_for_reply(int fd, unsigned timeout)
{
	fd_set readfds;
	struct timeval start, tm;
	
	gettimeofday(&start, NULL);

	for (;;) {
		tm.tv_usec = 0L;
		tm.tv_sec = (long) timeout;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		if (grad_recompute_timeout (&start, &tm)) 
			return 0;

		if (select(fd+1, &readfds, NULL, NULL, &tm) < 0) {
			if (errno == EINTR) {
				GRAD_DEBUG(20,
					   "select interrupted. retrying.");
				continue;
			}
			grad_log(GRAD_LOG_NOTICE, _("select() interrupted"));
			break;
		}

		return FD_ISSET (fd, &readfds);
	}
	return 1;
}

grad_request_t *
grad_client_send0(grad_server_queue_t *config, int port_type, int code,
		  grad_avp_t *pairlist,
		  int flags,
		  int *authid, u_char *authvec)
{
	struct sockaddr salocal;
	struct sockaddr saremote;
	struct sockaddr_in *sin;
        int sockfd;
        int salen;
        int i;
        grad_request_t *req = NULL;
        grad_server_t *server;
        char ipbuf[GRAD_IPV4_STRING_LENGTH];
	char *recv_buf;
	grad_iterator_t *itr;
	int id;
	
        if (port_type < 0 || port_type > 2) {
                grad_log(GRAD_LOG_ERR, _("invalid port type"));
                return NULL;
        }
        sockfd = socket(PF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "socket");
                return NULL;
        }

        sin = (struct sockaddr_in *) &salocal;
        memset (sin, 0, sizeof (salocal));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = config->source_ip ?
                                   htonl(config->source_ip) : INADDR_ANY;
        sin->sin_port = 0;
        if (bind(sockfd, &salocal, sizeof (struct sockaddr_in))) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "bind");
                close(sockfd);
                return NULL;
        }

	GRAD_DEBUG1(1, "sending %s", grad_request_code_to_name(code));
	recv_buf = grad_emalloc(config->buffer_size);
        itr = grad_iterator_create(config->servers);
        server = grad_iterator_first(itr);
        do {
		int result;
		u_char authenticator[GRAD_AUTHENTICATOR_LENGTH];
		void *pdu;
		size_t size;
		grad_avp_t *pair;

                if (server->port[port_type] <= 0)
                        continue;
                
                GRAD_DEBUG2(10, "server %s:%d",
                                 grad_ip_iptostr(server->addr, ipbuf),
                                 server->port[port_type]);

                if (authid && (flags & RADCLT_AUTHENTICATOR))
			memcpy(authenticator, authvec, sizeof authenticator);
		else
			grad_client_random_authenticator(authenticator);
		if (authid && (flags & RADCLT_ID))
			id = *authid;
		else
			id = grad_client_message_id(server);
		pair = grad_client_encrypt_pairlist(grad_avl_dup(pairlist),
						    authenticator,
						    server->secret);
		size = grad_create_pdu(&pdu, code,
				       id,
				       authenticator,
				       server->secret,
				       pair,
				       NULL);
		if (authid && !(flags & RADCLT_ID))
			*authid = id;
		if (authvec && !(flags & RADCLT_AUTHENTICATOR))
			memcpy(authvec, authenticator, sizeof authenticator);
		
		grad_avl_free(pair);
		
                if (size <= 0) 
                        break; /*FIXME: continue anyway?*/
        
                /* Now send the request. */
                
                sin = (struct sockaddr_in *) &saremote;
                memset(sin, 0, sizeof (saremote));
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(server->addr);
                sin->sin_port = htons(server->port[port_type]);

		GRAD_DEBUG2(10, "sending request (timeout=%u, retries=%u)",
			    config->timeout, config->retries);
		
                for (i = 0; i < config->retries; i++) {
			if (i)
				GRAD_DEBUG(10,"no response. retrying.");
				
			if (sendto(sockfd, pdu, size, 0,
                                   &saremote,
                                   sizeof(struct sockaddr_in)) == -1) {
                                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, "sendto");
                        }

                        salen = sizeof (saremote);

                        if (wait_for_reply (sockfd, config->timeout)) {
                                result = recvfrom(sockfd,
                                                  recv_buf,
                                                  config->buffer_size,
                                                  0, &saremote, &salen);

                                if (result > 0) 
                                        req = grad_client_recv(
						ntohl(sin->sin_addr.s_addr),
                                                ntohs(sin->sin_port),
                                                server->secret,
                                                authenticator,
                                                recv_buf,
                                                result);
                                else 
                                        grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
                                        _("error receiving data from %s:%d"),
                                                 grad_ip_iptostr(server->addr, ipbuf),
                                                 server->port[port_type]);
                                
                                break;
                        }
                }
		
		grad_free(pdu);
		
                if (!req)
                        GRAD_DEBUG2(10,"no reply from %s:%d",
				    grad_ip_iptostr(server->addr, ipbuf),
				    server->port[port_type]);
		
        } while (!req && (server = grad_iterator_next(itr)) != NULL);
	grad_iterator_destroy(&itr);

	grad_free(recv_buf);
        close(sockfd);
        return req;
}

grad_request_t *
grad_client_send(grad_server_queue_t *config, int port_type, int code,
		 grad_avp_t *pairlist)
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
#define TOK_DEBUG      5

static grad_keyword_t kwd[] = {
        { "source_ip", TOK_SOURCE_IP },
        { "source-ip", TOK_SOURCE_IP },
        { "server", TOK_SERVER },
        { "timeout", TOK_TIMEOUT },
        { "retry", TOK_RETRY },
	{ "debug", TOK_DEBUG },
        { NULL }
};

static int
parse_client_config(void *closure, int argc, char **argv, grad_locus_t *loc)
{
	grad_server_queue_t *client = closure;
        char *p;
        grad_server_t serv;
	int i;
	
        switch (grad_xlat_keyword(kwd, argv[0], TOK_INVALID)) {
        case TOK_INVALID:
                grad_log_loc(GRAD_LOG_ERR, loc, _("unknown keyword"));
                break;
                
        case TOK_SOURCE_IP:
                client->source_ip = grad_ip_gethostaddr(argv[1]);
                break;
                
        case TOK_SERVER:
                if (argc != 6) {
                        grad_log_loc(GRAD_LOG_ERR, loc, _("wrong number of fields"));
                        break;
                }
                memset(&serv, 0, sizeof serv);

                serv.name = argv[1];
                serv.addr = grad_ip_gethostaddr(argv[2]);
                if (!serv.addr) {
                        grad_log_loc(GRAD_LOG_ERR, loc,
				     _("bad IP address or host name"));
                        break;
                }
                
                serv.secret = argv[3];

                serv.port[0] = strtol(argv[4], &p, 0);
                if (*p) {
                        grad_log_loc(GRAD_LOG_ERR, loc, _("bad port number %s"),
				     argv[4]);
                        break;
                }

                serv.port[1] = strtol(argv[5], &p, 0);
                if (*p) {
                        grad_log_loc(GRAD_LOG_ERR, loc, _("bad port number %s"),
				     argv[4]);
                        break;
                }

		grad_client_append_server(client,
					  grad_client_alloc_server(&serv));
                break;
                
        case TOK_TIMEOUT:
                client->timeout = strtol(argv[1], &p, 0);
                if (*p) 
                        grad_log_loc(GRAD_LOG_ERR, loc,  _("bad timeout value"));
                break;
                
        case TOK_RETRY:
                client->retries = strtol(argv[1], &p, 0);
                if (*p) 
                        grad_log_loc(GRAD_LOG_ERR, loc, _("bad retry value"));
                break;

	case TOK_DEBUG:
		for (i = 1; i < argc; i++)
			grad_set_debug_levels(argv[i]);
		break;
        }
        return 0;
}


grad_server_queue_t *
grad_client_create_queue(int read_cfg, grad_uint32_t source_ip, size_t bufsize)
{
        grad_server_queue_t *client;
        char *filename;
        
        client = grad_emalloc(sizeof *client);

        /* Provide default values */
        client->source_ip = source_ip;
        client->timeout = 1;
        client->retries = 3;
        client->buffer_size = bufsize ? bufsize : 4096;
        client->servers = 0;

        if (read_cfg) {
                filename = grad_mkfilename(grad_config_dir, "client.conf");
                grad_read_raddb_file(filename, 1, NULL,
                                     parse_client_config, client);
                grad_free(filename);
        }
        return client;
}

void
grad_client_destroy_queue(grad_server_queue_t *queue)
{
	if (queue) {
		grad_client_clear_server_list(queue);
		grad_free(queue);
	}
}

grad_server_t *
grad_client_alloc_server(grad_server_t *src)
{
        grad_server_t *server;

        server = grad_emalloc(sizeof(*server));
        server->name = grad_estrdup(src->name);
        server->addr = src->addr;
        server->port[0] = src->port[0];
        server->port[1] = src->port[1];
        server->secret = grad_estrdup(src->secret);
	server->id_offset = (off_t)-1;
        return server;
}

grad_server_t *
grad_client_dup_server(grad_server_t *src)
{
        grad_server_t *dest;

        dest = grad_emalloc(sizeof(*dest));
        dest->addr = src->addr;
        dest->name = grad_estrdup(src->name);
        dest->port[0] = src->port[0];
        dest->port[1] = src->port[1];
        dest->secret = grad_estrdup(src->secret);
        return dest;
}

/* ************************************************************************* */
/* Functions to manipulate server lists
 */

void
grad_client_free_server(grad_server_t *server)
{
        grad_free(server->name);
        grad_free(server->secret);
        grad_free(server);
}

void
grad_client_append_server(grad_server_queue_t *qp, grad_server_t *server)
{
	if (!qp->servers)
		qp->servers = grad_list_create();
	grad_list_append(qp->servers, server);
}

static int
grad_client_internal_free_server(void *item, void *data)
{
	grad_server_t *server = item;
        grad_free(server->name);
        grad_free(server->secret);
	grad_free(server);
	return 0;
}

void
grad_client_clear_server_list(grad_server_queue_t *qp)
{
	grad_list_destroy(&qp->servers,
			  grad_client_internal_free_server, NULL);
}

static int
server_cmp(const void *item, const void *data)
{
	const grad_server_t *serv = item;
	const char *id = data;

        return strcmp(serv->name, id);
}

grad_server_t *
grad_client_find_server(grad_server_queue_t *qp, char *name)
{
	return grad_list_locate(qp->servers, name, server_cmp);
}

