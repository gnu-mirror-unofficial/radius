/* This file is part of GNU Radius.
   Copyright (C) 2002, 2003, 2004 Free Software Foundation
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <argcv.h>
#include <radius.h>
#include <envar.h>
#include <list.h>

static RAD_LIST /* of REALM */ *realms; 

struct _parse_data {
	int (*fun)();
	int ports[PORT_MAX];
	LOCUS *loc;
};

static int
_parse_server(int argc, char **argv, struct _parse_data *pd, int *np,
	      RADIUS_SERVER *srv)
{
	memset(srv, 0, sizeof(*srv));
	srv->name = argv[*np];
	srv->addr = grad_ip_gethostaddr(argv[(*np)++]);
	if (*np+1 < argc && argv[*np][0] == ':') {
		char *p;
		
                srv->port[PORT_AUTH] = strtoul(argv[++*np], &p, 0);
		if (*np+2 < argc && argv[*np+1][0] == ':') {
			++*np;
			srv->port[PORT_ACCT] = strtoul(argv[++*np], &p, 0);
		} else
			srv->port[PORT_ACCT] = srv->port[PORT_AUTH] + 1;
		++*np;
	} else {
		srv->port[PORT_AUTH] = pd->ports[PORT_AUTH];
		srv->port[PORT_ACCT] = pd->ports[PORT_ACCT];
	}
	if (pd->fun && pd->fun(srv)) {
		radlog_loc(L_ERR, pd->loc,
			   _("can't find secret for %s"),
			   srv->name);
		return 1; 
	}
	return 0;
}

static int
_parse_server_list(RADIUS_SERVER_QUEUE *qp, char *str, struct _parse_data *pd)
{
	int i, argc;
	char **argv;

	if (argcv_get(str, ",:", NULL, &argc, &argv)) 
		return 1;

	for (i = 0; i < argc; i++) {
		RADIUS_SERVER srv;
		if (_parse_server(argc, argv, pd, &i, &srv) == 0) 
			grad_client_append_server(qp, grad_client_alloc_server(&srv));

		if (i < argc && argv[i][0] != ',') {
			radlog_loc(L_ERR, pd->loc,
				   _("expected , but found %s"),
				   argv[i]);
			argcv_free(argc, argv);
			return 1;
		}
	}
	argcv_free(argc, argv);
	return 0;
}


/* read realms entry */
/*ARGSUSED*/
static int
read_realms_entry(void *closure, int fc, char **fv, LOCUS *loc)
{
	struct _parse_data *pd = closure;
        REALM *rp;
	int i;
	
        if (fc < 2) {
                radlog_loc(L_ERR, loc, _("too few fields (%d)"), fc);
                return -1;
        }

        pd->loc = loc;
	
        rp = emalloc(sizeof(REALM));
	rp->queue = NULL;
        if (strcmp(fv[1], "LOCAL") == 0) {
		i = 2;
	} else {
		rp->queue = grad_client_create_queue(0, 0, 0);
		i = 0;
		do {
			if (_parse_server_list(rp->queue, fv[++i], pd)) {
				grad_client_clear_server_list(rp->queue);
				break;
			}
		} while (fv[i][strlen(fv[i])-1] == ',') ;
		i++;
		
		if (grad_list_count(rp->queue->servers) == 0) {
			radlog_loc(L_NOTICE, loc, _("discarding entry"));
			grad_client_destroy_queue(rp->queue);
			efree(rp);
			return 0;
		}
	}

        STRING_COPY(rp->realm, fv[0]);
        
        if (i < fc) {
                rp->args = grad_envar_parse_argcv(fc-i, &fv[i]);

		if (rp->queue) {
			rp->queue->timeout = grad_envar_lookup_int(rp->args,
							      "timeout", 1);
			rp->queue->retries = grad_envar_lookup_int(rp->args,
							      "retries", 1);
		}
        }
	if (!realms)
		realms = grad_list_create();
        grad_list_prepend(realms, rp);
        return 0;
}

static int
_realm_mem_free(void *item, void *data ARG_UNUSED)
{
	REALM *r = item;
	grad_client_destroy_queue(r->queue);
	grad_envar_free_list(&r->args);
	efree(item);
	return 0;
}
	
/*
 * Read the realms file.
 */
int
grad_read_realms(char *file, int auth_port, int acct_port, int (*set_secret)())
{
	struct _parse_data pd;

	grad_list_destroy(&realms, _realm_mem_free, NULL);
        realms = NULL;
	pd.fun = set_secret;
	pd.ports[PORT_AUTH] = auth_port;
	pd.ports[PORT_ACCT] = acct_port;
        return grad_read_raddb_file(file, 1, read_realms_entry, &pd);
}

/* Realm Lookup Functions */

static int
realm_match_name_p(const REALM *realm, const char *name)
{
	return (grad_envar_lookup_int(realm->args, "ignorecase", 0) ?
		strcasecmp : strcmp) (realm->realm, name) == 0;
}

/* Find a realm in the REALM list */
REALM *
grad_realm_lookup_name(char *realm)
{
        REALM *p;
	ITERATOR *itr = iterator_create(realms);

	if (!itr)
		return NULL;

        for (p = iterator_first(itr); p; p = iterator_next(itr))
		if (realm_match_name_p(p, realm))
                        break;
	
        if (!p && strcmp(realm, "NOREALM")) {
        	for (p = iterator_first(itr); p; p = iterator_next(itr))
                        if (strcmp(p->realm, "DEFAULT") == 0)
                                break;
        }
        iterator_destroy(&itr);
        return p;
}

int
grad_realm_verify_ip(REALM *realm, UINT4 ip)
{
	RADIUS_SERVER *serv;
	ITERATOR *itr;

	if (!realm->queue
	    || (itr = iterator_create(realm->queue->servers)) == NULL)
		return 0;
	for (serv = iterator_first(itr); serv; serv = iterator_next(itr))
	     	if (serv->addr == ip)
			break;
	iterator_destroy(&itr);
	return serv != NULL;
}

REALM *
grad_realm_lookup_ip(UINT4 ip)
{
	REALM *p;
	ITERATOR *itr;

        if (!(itr = iterator_create(realms)))
	    return NULL;
        for (p = iterator_first(itr); p; p = iterator_next(itr))
		if (grad_realm_verify_ip(p, ip))
			break;
	iterator_destroy(&itr);
	return p;
}

int
grad_realm_strip_p(REALM *r)
{
	return grad_envar_lookup_int(r->args, "strip", 1);
}

size_t
grad_realm_get_quota(REALM *r)
{
	return grad_envar_lookup_int(r->args, "quota", 0);
}
		
