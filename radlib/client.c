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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <radiusd.h>
#include <radclient.h>

int radclient_debug;

static int radclient_build_request(RADCLIENT *config, SERVER *server, int code,
				   VALUE_PAIR *pair);
static AUTH_REQ * radclient_recv(UINT4 host, u_short udp_port,
				 char *secret, char *vector,
				 char *buffer,
				 int length);
static AUTH_REQ * decode_buffer(UINT4 host, u_short udp_port, char *buffer,
				int length);
static void random_vector(char *vector);
static SERVER * read_servers(char *config_dir);
static void read_config(RADCLIENT *client, char *config_dir);
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

AUTH_REQ *
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
	AUTH_REQ *req = NULL;
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
	sin->sin_addr.s_addr = INADDR_ANY;

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
	} while (!req && (server = server->next_avail) != NULL);
	
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
	char     md5buf[256];
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
			printf(_("send: "));
			fprint_attr_val(stdout, pair);
			printf("\n");
		}

		/*
		 *	This could be a vendor-specific attribute.
		 */
		length_ptr = NULL;
		if ((vendorcode = VENDOR(pair->attribute)) > 0 &&
		    (vendorpec  = dict_vendorpec(vendorcode)) > 0) {
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

#ifdef ATTRIB_NMC
		if (vendorpec == VENDORPEC_USR) {
			CHECKSIZE(2);
			lval = htonl(pair->attribute & 0xFFFF);
			memcpy(ptr, &lval, 4);
			total_length += 2;
			*length_ptr  += 2;
			ptr          += 4;
		} else
#endif
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
				       pair->strlength);

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


AUTH_REQ *
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
	md5_calc(calc_digest, (char *)auth, length + secretlen);

	if (memcmp(reply_digest, calc_digest, AUTH_VECTOR_LEN) != 0) {
		radlog(L_WARN, _("Received invalid reply digest from server"));
	}

	return decode_buffer(host, udp_port, buffer, length);
}


AUTH_REQ	*
decode_buffer(host, udp_port, buffer, length)
	UINT4 host;
	u_short udp_port;
	char *buffer;
	int length;
{
	u_char		*ptr;
	AUTH_HDR	*auth;
	int		totallen;
	int		attribute;
	int		attrlen;
	DICT_ATTR	*attr;
	UINT4		lval;
	VALUE_PAIR	*first_pair;
	VALUE_PAIR	*prev;
	VALUE_PAIR	*pair;
	AUTH_REQ	*authreq;

	/*
	 *	Pre-allocate the new request data structure
	 */

	authreq = alloc_request();

	auth = (AUTH_HDR *)buffer;
	totallen = ntohs(auth->length);

	/*
	 *	Fill header fields
	 */
	authreq->ipaddr = host;
	authreq->udp_port = udp_port;
	authreq->id = auth->id;
	authreq->code = auth->code;
	memcpy(authreq->vector, auth->vector, AUTH_VECTOR_LEN);

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
		if ((attr = dict_attrget(attribute)) == (DICT_ATTR *)NULL) {
			radlog(L_ERR,
			       _("Received unknown attribute %d"), attribute);
		} else if ( attrlen > AUTH_STRING_LEN ) {
			radlog(L_ERR,
			       _("attribute %d too long, %d > %d"), attribute,
			       attrlen, AUTH_STRING_LEN);
		} else {
			pair = alloc_pair();
			
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
				free_pair(pair);
				break;
			}

			if (radclient_debug && pair) {
				printf(_("recv: "));
				fprint_attr_val(stdout, pair);
				printf("\n");
			}

		}
		ptr += attrlen;
		length -= attrlen + 2;
	}
	authreq->request = first_pair;
	return authreq;
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


#define F_LOCALNAME 0
#define F_FQDN      1
#define F_SECRET    2
#define F_AUTH_PORT 3
#define F_ACCT_PORT 4
#define F_CNTL_PORT 5
#define FN 6

SERVER *
read_servers(config_dir)
	char *config_dir;
{
	FILE        *fp;
	int         line_no;
	int         errcnt;
	char        *name;
	int         i;
	char        linebuf[128];
	char        *start, *p;
	int         fn;
	int         len;
	UINT4       addr;
	char        *field[FN];
	SERVER      *first, *last, *sp;
	
	name = mkfilename(config_dir, RADCLIENT_SHADOW);
	fp = fopen(name, "r");
	if (!fp) {
		radlog(L_ERR|L_PERROR,
		       _("can't open `%s' for reading"),
		       name);
		efree(name);
		return NULL;
	}
	
	line_no = 0;
	first = last = NULL;
	while (fgets(linebuf, sizeof linebuf, fp)) {
		line_no++;
		if (linebuf[0] == '#')
			continue;

		len = strlen(linebuf);
		if (len <= 1)
			continue;
		if (linebuf[len-1] == '\n')
			linebuf[len-1] = 0;

		/*
		 * Parse the line
		 */
		fn = 0;
		start = linebuf;
		while (*start) {
			if (fn >= FN) {
				radlog(L_WARN,
				       _("%s:%d: extra fields"),
				       name, line_no);
				break;
			}
			field[fn++] = start;
			for (p = start; *p && *p != ':'; p++)
				;
			if (!*p)
				break;
			else
				*p++ = 0;
			start = p;
		}
		if (fn != FN) {
			radlog(L_ERR,
			       _("%s:%d: not enough fields"),
			       name, line_no);
			continue;
		}

		/*
		 * Verify semantics
		 */
		errcnt = 0;
		if (field[F_LOCALNAME][0] == 0) {
			radlog(L_ERR,
			       _("%s:%d: empty local name"),
			       name, line_no);
			errcnt++;
		}
		if (field[F_FQDN][0] == 0) {
			radlog(L_ERR,
			       _("%s:%d: empty host address"),
			       name, line_no);
			errcnt++;
		}
		addr = get_ipaddr(field[F_FQDN]);
		if (addr == 0) {
			radlog(L_ERR,
			       _("%s:%d: unknown host %s"),
			       name, line_no,
			       field[0]);
			errcnt++;
		}
		if (field[F_SECRET][0] == 0) {
			radlog(L_ERR,
			       _("%s:%d: empty secret key"),
			       name, line_no);
			errcnt++;
		} else if (strlen(field[F_SECRET]) >= sizeof(sp->secret)) {
			radlog(L_ERR,
			       _("%s:%d: secret key too long"),
			       name, line_no);
			errcnt++;
		}
		
		for (i = 0; i < 3; i++) {
			for (p = field[F_AUTH_PORT+i]; *p; p++)
				if (!isdigit(*p))
					break;
			if (*p) {
				radlog(L_ERR,
				       _("%s:%d: field %d not a number"),
				       name, line_no, F_AUTH_PORT+i);
				errcnt++;
			}
		}

		if (errcnt)
			continue;

		/*
		 * Allocate SERVER structure
		 */
		sp = alloc_entry(sizeof *sp);
		
		sp->addr = addr;
		sp->name = estrdup(field[F_LOCALNAME]);
		strcpy(sp->secret, field[F_SECRET]);
		sp->port[PORT_AUTH] = field[F_AUTH_PORT][0] ? 
		                   atoi(field[F_AUTH_PORT]) : PW_AUTH_UDP_PORT;
		sp->port[PORT_ACCT] = field[F_ACCT_PORT][0] ? 
		                   atoi(field[F_ACCT_PORT]) : PW_ACCT_UDP_PORT;
		sp->port[PORT_CNTL] = atoi(field[F_CNTL_PORT]);
		if (!first)
			first = sp;
		else
			last->next = sp;
		last = sp;
	}
	fclose(fp);
	efree(name);
	return first;
}

/* ************************************************************************* */
/* Functions to manipulate server lists
 */

/* Static functions */
static int add_server(SERVER **first, SERVER *new_server);
static int delete_server(SERVER **first, char *name);

int
add_server(first, new_server)
	SERVER **first;
	SERVER *new_server;
{
	SERVER *sp, *prev;
	
	new_server->next_avail = NULL;
	if (!*first) {
		*first = new_server;
		return 0;
	}
	
	sp = *first;
	while (sp) {
		if (strcmp(sp->name, new_server->name) == 0)
			return 1;
		prev = sp;
		sp = sp->next_avail;
	}
	prev->next_avail = sp;
	return 0;
}

int
delete_server(first, name)
	SERVER **first;
	char *name;
{
	SERVER *sp, *prev;
	
	if (!*first) 
		return 0;
	
	sp = *first;
	prev = NULL;
	while (sp) {
		if (strcmp(sp->name, name) == 0)
			break;
		prev = sp;
		sp = sp->next_avail;
	}
	if (!sp)
		return 1;
	if (prev)
		prev->next_avail = sp->next_avail;
	else
		*first = sp->next_avail;
	return 0;
}

SERVER *
find_server(server, name)
	SERVER *server;
	char *name;
{
	while (server) {
		if (strcmp(server->name, name) == 0)
			break;
		server = server->next;
	}
	return server;
}

/* global functions */

SERVER *
radclient_find_server(config, name)
	RADCLIENT *config;
	char *name;
{
	return find_server(config->server, name);
}

int
radclient_delete_server(config, name)
	RADCLIENT *config;
	char *name;
{
	if (!name) {
		config->first_server = NULL;
		return 0;
	}
	return delete_server(&config->first_server, name);
}
		
int
radclient_add_server(config, name)
	RADCLIENT *config;
	char *name;
{
	SERVER *sp;
	
	if (!name) {
		/* Add whole list */
		for (sp = config->server; sp; sp = sp->next)
			sp->next_avail = sp->next;
		config->first_server = config->server;
		return 0;
	}
	if ((sp = radclient_find_server(config, name)) == NULL)
		return 1;
	return add_server(&config->first_server, sp);
}
		
/* ************************************************************************* */
/* Initialization, config files &c. */

enum {
	KW_TIMEOUT,
	KW_RETRY,
	KW_BUFSIZE,
	KW_SERVER,
};

static struct keyword config_keyword[] = {
	"timeout",    KW_TIMEOUT,
	"retry",      KW_RETRY,
	"bufsize",    KW_BUFSIZE,
	"server",     KW_SERVER,
	0
};

static void get_number(char *arg, int *vp, char *name, int line_no);
static void get_size(char *arg, size_t *vp, char *name, int line_no);

void
get_number(arg, vp, name, line_no)
	char *arg;
	int *vp;
	char *name;
	int line_no;
{
	char *p;
	int value;

	value = strtol(arg, &p, 0);
	if (*p) 
		radlog(L_ERR,
		       _("%s:%d: expected number"),
		       name, line_no);
	else
		*vp = value;
}

void
get_size(arg, vp, name, line_no)
	char *arg;
	size_t *vp;
	char *name;
	int line_no;
{
	char *p;
	size_t value;

	value = (size_t) strtol(arg, &p, 0);
	if (*p) 
		radlog(L_ERR,
		       _("%s:%d: expected number"),
		       name, line_no);
	else
		*vp = value;
}

void
read_config(client, config_dir)
	RADCLIENT *client;
	char *config_dir;
{
	char       *name;
	FILE       *fp;
	int        line_no;
	int        len;
	char       linebuf[128];
	char       *start, *arg, *p;
	SERVER     *sp;
	
	name = mkfilename(config_dir, RADCLIENT_CONFIG);
	fp = fopen(name, "r");
	if (!fp) {
		if (errno != ENOENT) {
			radlog(L_ERR|L_PERROR,
			       _("can't open `%s' for reading"),
			       name);
		}
		efree(name);
		return;
	}

	line_no = 0;
	while (fgets(linebuf, sizeof linebuf, fp)) {
		line_no++;
		len = strlen(linebuf);
		if (len ==  0)
			continue;
		if (linebuf[len-1] == '\n')
			linebuf[len-1] = 0;

		/*
		 * Get command word
		 */
		for (p = linebuf; *p; p++)
			if (!isspace(*p))
				break;
		if (!*p || *p == '#')
			continue;
		start = p;
		while (*p && !isspace(*p))
			p++;

		/*
		 * Get argument
		 */
		if (*p) {
			*p++ = 0;
			while (*p && isspace(*p))
				p++;
			arg = p;
			while (*p && !isspace(*p))
				p++;
			if (*p)
				*p = 0;
			if (arg[0] == 0 || arg[0] == '#')
				arg = NULL;
		} else
			arg = NULL;

		if (!arg) {
			radlog(L_ERR,
			       _("%s:%d: syntax error"),
			       name, line_no);
			continue;
		}
		switch (xlat_keyword(config_keyword, start, -1)) {
		case KW_TIMEOUT:
			get_number(arg, &client->timeout, name, line_no);
			break;
		case KW_RETRY:
			get_number(arg, &client->retries, name, line_no);
			break;
		case KW_BUFSIZE:
			get_size(arg, &client->bufsize, name, line_no);
			break;
		case KW_SERVER:
			sp = radclient_find_server(client, arg);
			if (!sp) {
				radlog(L_ERR,
				       _("%s:%d: unknown server: %s"),
				       name, line_no, arg);
				break;
			}
			add_server(&client->first_server, sp);
			break;
		default:
			radlog(L_ERR,
			       _("%s:%d: unknown keyword"),
			       name, line_no);
		}
	}
	fclose(fp);
	efree(name);
}

RADCLIENT *
radclient_init(config_dir)
	char *config_dir;
{
	RADCLIENT *client;
	SERVER *server;
	
	if (!config_dir)
		config_dir = radius_dir;
	server = read_servers(config_dir);
	if (!server)
		return NULL;

	client = emalloc(sizeof *client);

	client->timeout = 1;
	client->retries = 3;
	client->bufsize = 4096;
	client->server = server;

	read_config(client, config_dir);

	client->data_buffer = emalloc(client->bufsize);
	client->messg_id = getpid() % 256;

	return client;
}






