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
#include <radclient.h>
#include <slist.h>

int radclient_debug;

static int radclient_build_request(RADCLIENT *config, SERVER *server, int code,
				   VALUE_PAIR *pair);
static RADIUS_REQ * radclient_recv(UINT4 host, u_short udp_port,
				 char *secret, char *vector,
				 char *buffer,
				 int length);
static RADIUS_REQ * decode_buffer(UINT4 host, u_short udp_port, char *buffer,
				int length);
static void random_vector(char *vector);
static char * auth_code_str(int code);

static struct keyword auth_codes[] = {
#define D(a) #a, a	
	D(PW_AUTHENTICATION_REQUEST),
	D(PW_AUTHENTICATION_ACK),
	D(PW_AUTHENTICATION_REJECT),
	D(PW_ACCOUNTING_REQUEST),
	D(PW_ACCOUNTING_RESPONSE),
	D(PW_ACCOUNTING_STATUS),
	D(PW_PASSWORD_REQUEST),
	D(PW_PASSWORD_ACK),
	D(PW_PASSWORD_REJECT),
	D(PW_ACCOUNTING_MESSAGE),
	D(PW_ACCESS_CHALLENGE),
	D(PW_ASCEND_TERMINATE_SESSION),
	0
#undef D	
};

char *
auth_code_str(code)
	int code;
{
	struct keyword *p;

	for (p = auth_codes; p->name; p++)
		if (p->tok == code)
			return p->name;
	return NULL;
}

RADIUS_REQ *
radclient_send(config, port_type, code, pair)
	RADCLIENT *config;
	int port_type;
	int code;
	VALUE_PAIR *pair;
{
	struct	sockaddr	salocal;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sin;
	int local_port;
	int sockfd;
	int salen;
	int total_length;
	fd_set readfds;
	struct timeval tm;
	int result;
	int i;
	RADIUS_REQ *req = NULL;
	SERVER *server;

	if (port_type < 0 || port_type > 2) {
		radlog(L_ERR, _("invalid port type"));
		return NULL;
	}
	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		radlog(L_ERR, _("can't open socket: %s"), strerror(errno));
		return NULL;
	}

	sin = (struct sockaddr_in *) &salocal;
        memset (sin, 0, sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = config->source_ip ?
		                   htonl(config->source_ip) : INADDR_ANY;

	local_port = 1025;
	do {
		local_port++;
		sin->sin_port = htons((u_short)local_port);
	} while ((bind(sockfd, &salocal, sizeof (struct sockaddr_in)) < 0) &&
						local_port < 64000);
	if (local_port >= 64000) {
		radlog(L_ERR, _("can't bind: %s"), strerror(errno));
		close(sockfd);
		return NULL;
	}

	server = config->first_server;
	do {
		if (server->port[port_type] <= 0)
			continue;
		
		total_length = radclient_build_request(config, server,
						       code, pair);
	
		if (total_length <= 0) 
			break;
	
		/*
		 *	Send the request we've built.
		 */
		
		sin = (struct sockaddr_in *) &saremote;
		memset(sin, 0, sizeof (saremote));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(server->addr);
		sin->sin_port = htons(server->port[port_type]);
		
		for (i = 0; i < config->retries; i++) {
			sendto(sockfd, config->data_buffer, total_length, 0,
			       &saremote, sizeof(struct sockaddr_in));

			salen = sizeof (saremote);

			tm.tv_usec = 0L;
			tm.tv_sec = (long) config->timeout;
			FD_ZERO(&readfds);
			FD_SET(sockfd, &readfds);
			if (select(sockfd+1, &readfds, NULL, NULL, &tm) < 0) {
				if (errno == EINTR)
					continue;
				radlog(L_NOTICE, _("select() interrupted"));
				break;
			}

			if (FD_ISSET (sockfd, &readfds)) {
				result = recvfrom(sockfd,
						  config->data_buffer,
						  config->bufsize,
						  0, &saremote, &salen);

				if (result > 0) 
					req = radclient_recv(
						sin->sin_addr.s_addr,
					        sin->sin_port,
					        server->secret,
					        config->vector,
            					config->data_buffer,
				        	result);
				else 
					radlog(L_ERR|L_PERROR,
					       _("error receiving data from %s:%d"),
					       ip_hostname(server->addr),
					       server->port[port_type]);
				
				break;
			}
		}
	} while (!req && (server = server->next) != NULL);
	
	close(sockfd);
	return req;
}

int
radclient_build_request(config, server, code, pair)
	RADCLIENT *config;
	SERVER *server;
	int code;
	VALUE_PAIR *pair;
{
	int      total_length;
	int      attrlen;
	AUTH_HDR *auth;
	char     passbuf[AUTH_PASS_LEN];
	u_char   md5buf[256];
	char     *ptr, *length_ptr;
	int      secretlen;
	int      i;
	long     lval;
	int      vendorcode, vendorpec;
	
#define CHECKSIZE(l) if (ptr + l >= config->data_buffer + config->bufsize) \
	                 goto overflow;
	
	/*
	 *	Build an authentication request
	 */
	auth = (AUTH_HDR *)config->data_buffer;
	auth->code = code;
	auth->id = config->messg_id++ % 256;
	random_vector(config->vector);
	memcpy(auth->vector, config->vector, AUTH_VECTOR_LEN);
	total_length = AUTH_HDR_LEN;
	ptr = auth->data;

	if (radclient_debug) {
		char *name = auth_code_str(auth->code);
		printf("send code ");
		if (name) 
			printf("%d (%s)\n", auth->code, name);
		else
			printf("%d\n", auth->code);
	}
	for (; pair; pair = pair->next) {

		if (radclient_debug) {
			radfprintf(stdout, "%10.10s: %A\n", _("send"), pair);
		}

		/*
		 *	This could be a vendor-specific attribute.
		 */
		length_ptr = NULL;
		if ((vendorcode = VENDOR(pair->attribute)) > 0 &&
		    (vendorpec  = vendor_id_to_pec(vendorcode)) > 0) {
			CHECKSIZE(6);
			*ptr++ = DA_VENDOR_SPECIFIC;
			length_ptr = ptr;
			*ptr++ = 6;
			lval = htonl(vendorpec);
			memcpy(ptr, &lval, 4);
			ptr += 4;
			total_length += 6;
		} else if (pair->attribute > 0xff) {
			/*
			 *	Ignore attributes > 0xff
			 */
			pair = pair->next;
			continue;
		} else
			vendorpec = 0;

		*ptr++ = (pair->attribute & 0xFF);

		switch (pair->type) {
		case PW_TYPE_STRING:
			/* attrlen always < AUTH_STRING_LEN */
			if (pair->attribute == DA_PASSWORD) {
				char *p;

				attrlen = AUTH_PASS_LEN;
				CHECKSIZE(AUTH_PASS_LEN+2);
				*ptr++ = attrlen + 2;
				memset(passbuf, 0, attrlen);
				memcpy(passbuf, pair->strvalue,
				       pair->strlength < AUTH_PASS_LEN ?
                                              pair->strlength : AUTH_PASS_LEN);

				/* Calculate the MD5 Digest */
				secretlen = strlen(server->secret);
				strcpy(md5buf, server->secret);
				memcpy(md5buf + secretlen, auth->vector,
				       AUTH_VECTOR_LEN);
				md5_calc(ptr, md5buf,
					 secretlen + AUTH_VECTOR_LEN);
				
				/* Xor the password into the MD5 digest */
				p = ptr;
				for (i = 0; i < AUTH_PASS_LEN; i++) 
					*p++ ^= passbuf[i];
				
			} else {
				attrlen = pair->strlength;
				CHECKSIZE(attrlen+2);
				*ptr++ = attrlen + 2;
				memcpy(ptr, pair->strvalue, attrlen);
			}
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
			attrlen = sizeof(UINT4);
			CHECKSIZE(attrlen+2);
			*ptr++ = attrlen + 2;
			lval = htonl(pair->lvalue);
			memcpy(ptr, &lval, sizeof(UINT4));
			break;
		default:
			radlog(L_ERR, _("unknown attribute type"));
			return -1;
		}
		if (length_ptr)
			*length_ptr += attrlen + 2;
		ptr += attrlen;
		total_length += attrlen + 2;
	}

	auth->length = htons(total_length);
	return total_length;
	
overflow:
	radlog(L_ERR, _("build_request(): data buffer overflow"));
	return -1;
}


RADIUS_REQ *
radclient_recv(host, udp_port, secret, vector, buffer, length)
	UINT4 host;
	u_short udp_port;
	char *secret;
	char *vector;
	char *buffer;
	int length;
{
	AUTH_HDR	*auth;
	int		totallen;
	char		reply_digest[AUTH_VECTOR_LEN];
	char		calc_digest[AUTH_VECTOR_LEN];
	int		secretlen;
	
	auth = (AUTH_HDR *)buffer;
	totallen = ntohs(auth->length);

	if (totallen != length) {
		radlog(L_ERR,
		       _("Received invalid reply length from server (want %d/ got %d)"),
		       totallen, length);
		return NULL;
	}

	/* Verify the reply digest */
	memcpy(reply_digest, auth->vector, AUTH_VECTOR_LEN);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
	secretlen = strlen(secret);
	memcpy(buffer + length, secret, secretlen);
	md5_calc(calc_digest, (unsigned char *)auth, length + secretlen);

	if (memcmp(reply_digest, calc_digest, AUTH_VECTOR_LEN) != 0) {
		radlog(L_WARN, _("Received invalid reply digest from server"));
	}

	return decode_buffer(host, udp_port, buffer, length);
}


RADIUS_REQ *
decode_buffer(host, udp_port, buffer, length)
	UINT4 host;
	u_short udp_port;
	char *buffer;
	int length;
{
	u_char		*ptr;
	AUTH_HDR	*auth;
	int		attribute;
	int		attrlen;
	DICT_ATTR	*attr;
	UINT4		lval;
	VALUE_PAIR	*first_pair;
	VALUE_PAIR	*prev;
	VALUE_PAIR	*pair;
	RADIUS_REQ	*radreq;

	/*
	 *	Pre-allocate the new request data structure
	 */

	radreq = radreq_alloc();

	auth = (AUTH_HDR *)buffer;

	/*
	 *	Fill header fields
	 */
	radreq->ipaddr = host;
	radreq->udp_port = udp_port;
	radreq->id = auth->id;
	radreq->code = auth->code;
	memcpy(radreq->vector, auth->vector, AUTH_VECTOR_LEN);

	/*
	 *	Extract attribute-value pairs
	 */
	ptr = (u_char *)auth->data;
	length -= AUTH_HDR_LEN;
	first_pair = (VALUE_PAIR *)NULL;
	prev = (VALUE_PAIR *)NULL;

	if (radclient_debug) {
		char *name = auth_code_str(auth->code);
		printf("recv code ");
		if (name) 
			printf("%d (%s)\n", auth->code, name);
		else
			printf("%d\n", auth->code);
	}
	
	while (length > 0) {

		attribute = *ptr++;
		attrlen = *ptr++;
		if (attrlen < 2) {
			length = 0;
			continue;
		}
		attrlen -= 2;
		if ((attr = attr_number_to_dict(attribute)) == (DICT_ATTR *)NULL) {
			radlog(L_ERR,
			       _("Received unknown attribute %d"), attribute);
		} else if ( attrlen > AUTH_STRING_LEN ) {
			radlog(L_ERR,
			       _("attribute %d too long, %d > %d"), attribute,
			       attrlen, AUTH_STRING_LEN);
		} else {
			pair = avp_alloc();
			
			pair->name = attr->name;
			pair->attribute = attr->value;
			pair->type = attr->type;
			pair->next = (VALUE_PAIR *)NULL;

			switch (attr->type) {

			case PW_TYPE_STRING:
				pair->strvalue = alloc_string(attrlen + 1);
				memcpy(pair->strvalue, ptr, attrlen);
				pair->strvalue[attrlen] = '\0';
				pair->strlength = attrlen;
				if (first_pair == (VALUE_PAIR *)NULL) {
					first_pair = pair;
				} else {
					prev->next = pair;
				}
				prev = pair;
				break;
			
			case PW_TYPE_INTEGER:
			case PW_TYPE_IPADDR:
				memcpy(&lval, ptr, sizeof(UINT4));
				pair->lvalue = ntohl(lval);
				if (first_pair == (VALUE_PAIR *)NULL) {
					first_pair = pair;
				} else {
					prev->next = pair;
				}
				prev = pair;
				break;
			
			default:
				radlog(L_ERR,
				       _("    %s (Unknown Type %d)"),
				       attr->name, attr->type);
				avp_free(pair);
				break;
			}

			if (radclient_debug && pair) {
				radfprintf(stdout, "%10.10s: %A\n", 
						_("recv"), pair);
			}

		}
		ptr += attrlen;
		length -= attrlen + 2;
	}
	radreq->request = first_pair;
	return radreq;
}

/*
 *	Generate a random vector.
 */
void
random_vector(vector)
	char *vector;
{
	int	randno;
	int	i;

	srand(time(NULL));
	for (i = 0; i < AUTH_VECTOR_LEN; ) {
		randno = rand();
		memcpy(vector, &randno, sizeof(int));
		vector += sizeof(int);
		i += sizeof(int);
	}
}

/* ************************************************************************* */
/* Initialization. */

RADCLIENT *
radclient_alloc(source_ip, bufsize)
	UINT4 source_ip;
	size_t bufsize;
{
	RADCLIENT *client;

	client = emalloc(sizeof *client);

	/* Provide default values */
	client->source_ip = source_ip;
	client->timeout = 1;
	client->retries = 3;
	client->bufsize = bufsize ? bufsize : 4096;
	client->first_server = NULL;
	client->data_buffer = emalloc(client->bufsize);
	client->messg_id = getpid() % 256;

	return client;
}

SERVER *
radclient_alloc_server(src)
	SERVER *src;
{
	SERVER *server;

	server = alloc_entry(sizeof(*server));
	server->name = make_string(src->name);
	server->addr = src->addr;
	server->port[0] = src->port[0];
	server->port[1] = src->port[1];
	server->port[2] = src->port[2];
	strncpy(server->secret, src->secret, AUTH_PASS_LEN);
	server->secret[AUTH_PASS_LEN] = 0;
	return server;
}

SERVER *
radclient_dup_server(src)
	SERVER *src;
{
	SERVER *dest;

	dest = alloc_entry(sizeof(*dest));
	dest->addr = src->addr;
	dest->name = dup_string(src->name);
	dest->port[0] = src->port[0];
	dest->port[1] = src->port[1];
	dest->port[2] = src->port[2];
	strncpy(dest->secret, src->secret, AUTH_PASS_LEN);
	return dest;
}

/* ************************************************************************* */
/* Functions to manipulate server lists
 */

void
radclient_free_server(server)
	SERVER *server;
{
	free_string(server->name);
	free_entry(server);
}

SERVER *
radclient_append_server(list, server)
	SERVER *list;
	SERVER *server;
{
	return (SERVER*)append_slist((struct slist*)list,
				     (struct slist*)server);
}

void
radclient_internal_free_server(server)
	SERVER *server;
{
	free_string(server->name);
}

void
radclient_clear_server_list(list)
	SERVER *list;
{
	free_slist((struct slist *)list, radclient_internal_free_server);
}

int
server_cmp(serv, id)
	SERVER *serv;
	char *id;
{
	return strcmp(serv->name, id);
}

SERVER *
radclient_find_server(list, name)
	SERVER *list;
	char *name;
{
	return (SERVER*)find_slist((struct slist *)list,
				   server_cmp,
				   name);
}

