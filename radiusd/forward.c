/* This file is part of GNU Radius.
   Copyright (C) 2003, Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <radiusd.h>

struct forward_data {
	int type;
	struct sockaddr_in addr;
};

struct request_data {
	int type;
	void *ptr;
	size_t size;
};

static int forward_fd = -1;
static RAD_LIST *forward_list;

static void
add_forward(int type, UINT4 ip, int port)
{
	struct forward_data *fp;

	if (!forward_list) {
		forward_list = list_create();
		if (!forward_list) 
			return; /* FIXME */
	}
		
	fp = emalloc(sizeof(*fp));
	fp->type = type;
	fp->addr.sin_addr.s_addr = htonl(ip);
	fp->addr.sin_port = htons(port);
	list_append(forward_list, fp);
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
	
static int
forwarder(void *item, void *data)
{
	struct forward_data *f = item;
	struct request_data *r = data;
	int rc;

	if (f->type == r->type) {
		rc = sendto(forward_fd, r->ptr, r->size, 0,
			    (struct sockaddr *)&f->addr, sizeof(f->addr));
		if (rc < 0) {
			char buffer[DOTTED_QUAD_LEN];
			ip_iptostr(ntohl(f->addr.sin_addr.s_addr), buffer);
			radlog(L_ERR|L_PERROR,
			       _("Can't send to %s:%d"),
			       buffer, ntohs(f->addr.sin_port));
		}
	}
	return 0;
}

static int
free_mem(void *item, void *data ARG_UNUSED)
{
	efree(item);
	return 0;
}

static void
forward_before_config_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	close(forward_fd);
	forward_fd = -1;
	list_destroy(&forward_list, free_mem, NULL);
}

void
forward_init()
{
	radiusd_set_preconfig_hook(forward_before_config_hook, NULL, 0);
}

void
forward_request(int type, void *data, size_t size)
{
	struct request_data rd;

	if (!forward_list)
		return;
	
	if (forward_fd == -1) {
		forward_fd = socket(PF_INET, SOCK_DGRAM, 0);

		if (forward_fd == -1) {
			radlog(L_ERR|L_PERROR,
			       _("Can't open forwarding socket"));
			return;
		}
	}
	rd.type = type;
	rd.ptr = data;
	rd.size = size;
	list_iterate(forward_list, forwarder, &rd);
}
