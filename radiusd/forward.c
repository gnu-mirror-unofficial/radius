/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <radiusd.h>

struct request_data {
	int type;
	radiusd_request_t *req;
};

static int forward_fd = -1;
static grad_list_t *forward_list;

static void
add_forward(int type, grad_uint32_t ip, int port)
{
	grad_server_t *srv;

	if (!forward_list) {
		forward_list = grad_list_create();
		if (!forward_list) 
			return; /* FIXME */
	}
		
	srv = grad_emalloc(sizeof(*srv));
	srv->name = NULL;
	srv->addr = ip;
	srv->port[type] = port;
	grad_list_append(forward_list, srv);
}

static int
rad_cfg_forward(int argc, cfg_value_t *argv, int type, int defport)
{
	int i, errcnt = 0;
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) {
		for (i = 1; i < argc; i++) {
			add_forward(type,
				    argv[i].v.host.ipaddr,
				    argv[i].v.host.port > 0 ?
				    argv[i].v.host.port : defport);
		}
	}
	return 0;
}

int
rad_cfg_forward_auth(int argc, cfg_value_t *argv,
		     void *block_data, void *handler_data)
{
	return rad_cfg_forward(argc, argv, R_AUTH, auth_port);
}
	
int
rad_cfg_forward_acct(int argc, cfg_value_t *argv,
		     void *block_data, void *handler_data)
{
	return rad_cfg_forward(argc, argv, R_ACCT, acct_port);
}


static void
forward_data(grad_server_t *srv, int type, void *data, size_t size)
{
	int rc;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(srv->addr);
	addr.sin_port = htons(srv->port[type]);

	rc = sendto(forward_fd, data, size, 0,
		    (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		char buffer[GRAD_IPV4_STRING_LENGTH];

		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("Can't forward to %s:%d"),
		         grad_ip_iptostr(srv->addr, buffer),
		         srv->port[type]);
	}
}

static int
forwarder(void *item, void *data)
{
	grad_server_t *srv = item;
	struct request_data *r = data;
	int rc;

	if (srv->port[r->type] != 0) {
		grad_avp_t *vp = NULL, *plist;
		void *pdu;
		size_t size;
		int id;
		u_char *secret;
		
		if (srv->secret) {
			secret = srv->secret;
			vp = proxy_request_recode(r->req,
						  grad_avl_dup(r->req->request->avlist),
						  secret,
						  r->req->request->authenticator);
			plist = vp;
			id = grad_client_message_id(srv);
		} else {
			secret = r->req->request->secret;
			plist = r->req->request->avlist;
			id = r->req->request->id;
		}
		size = grad_create_pdu(&pdu,
				       r->req->request->code,
				       id,
				       r->req->request->authenticator,
				       secret,
				       plist,
				       NULL);
		grad_avl_free(vp);
		forward_data(srv, r->type, pdu, size);
		grad_free(pdu);
	}
	return 0;
}

static int
free_mem(void *item, void *data ARG_UNUSED)
{
	grad_free(item);
	return 0;
}

static void
forward_before_config_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	close(forward_fd);
	forward_fd = -1;
	grad_list_destroy(&forward_list, free_mem, NULL);
}

static int
fixup_forward_server(void *item, void *data)
{
	grad_server_t *srv = item;
	CLIENT *cl = client_lookup_ip(srv->addr);
	if (!cl) {
		char buffer[GRAD_IPV4_STRING_LENGTH];
		grad_log(GRAD_LOG_NOTICE,
		         _("Forwarding host %s not listed in clients"),
		         grad_ip_iptostr(srv->addr, buffer));
	} else
		srv->secret = cl->secret;
	return 0;
}

static void
forward_after_config_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	struct sockaddr_in s;
	
	if (grad_list_count(forward_list) == 0)
		return;
	
	forward_fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (forward_fd == -1) {
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
		         _("Can't open forwarding socket"));
		return;
	}

        memset (&s, 0, sizeof (s));
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(ref_ip);
	s.sin_port = 0;
	if (bind(forward_fd, (struct sockaddr*)&s, sizeof (s)) < 0) 
		grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
		         _("Can't bind forwarding socket"));
	
	grad_list_iterate(forward_list, fixup_forward_server, NULL);
}

void
forward_init()
{
	radiusd_set_preconfig_hook(forward_before_config_hook, NULL, 0);
	radiusd_set_postconfig_hook(forward_after_config_hook, NULL, 0);
}

void
forward_request(int type, radiusd_request_t *req)
{
	struct request_data rd;

	if (!forward_list || forward_fd == -1) 
		return;
	
	switch (type) {
	case R_AUTH:
	case R_ACCT:
		break;
	default:
		return;
	}
	
	rd.type = type;
	rd.req = req;
	grad_list_iterate(forward_list, forwarder, &rd);
}

