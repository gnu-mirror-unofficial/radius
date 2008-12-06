/* This file is part of GNU Radius.
   Copyright (C) 2002, 2003, 2004, 2005, 2007,
   2008 Free Software Foundation
  
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

#include <stdlib.h>
#include <radlib.h>

static grad_list_t /* of grad_realm_t */ *realms; 

struct _parse_data {
	int (*fun)();
	int ports[GRAD_PORT_MAX];
	grad_locus_t *loc;
};

static int
_parse_server(int argc, char **argv, struct _parse_data *pd, int *np,
	      grad_server_t *srv)
{
	memset(srv, 0, sizeof(*srv));
	srv->name = argv[*np];
	srv->addr = grad_ip_gethostaddr(argv[(*np)++]);
	if (*np+1 < argc && argv[*np][0] == ':') {
		char *p;
		
                srv->port[GRAD_PORT_AUTH] = strtoul(argv[++*np], &p, 0);
		if (*np+2 < argc && argv[*np+1][0] == ':') {
			++*np;
			srv->port[GRAD_PORT_ACCT] = strtoul(argv[++*np], &p, 0);
		} else
			srv->port[GRAD_PORT_ACCT] = srv->port[GRAD_PORT_AUTH] + 1;
		++*np;
	} else {
		srv->port[GRAD_PORT_AUTH] = pd->ports[GRAD_PORT_AUTH];
		srv->port[GRAD_PORT_ACCT] = pd->ports[GRAD_PORT_ACCT];
	}
	if (pd->fun && pd->fun(srv)) {
		grad_log_loc(GRAD_LOG_ERR, pd->loc,
			     _("can't find secret for %s"),
			     srv->name);
		return 1; 
	}
	return 0;
}

static int
_parse_server_list(grad_server_queue_t *qp, char *str, struct _parse_data *pd)
{
	int i, argc;
	char **argv;

	if (grad_argcv_get(str, ",:", NULL, &argc, &argv)) 
		return 1;

	for (i = 0; i < argc; i++) {
		grad_server_t srv;
		if (_parse_server(argc, argv, pd, &i, &srv) == 0) 
			grad_client_append_server(qp,
					      grad_client_alloc_server(&srv));

		if (i < argc && argv[i][0] != ',') {
			grad_log_loc(GRAD_LOG_ERR, pd->loc,
				     _("expected , but found %s"),
				     argv[i]);
			grad_argcv_free(argc, argv);
			return 1;
		}
	}
	grad_argcv_free(argc, argv);
	return 0;
}


/* read realms entry */
/*ARGSUSED*/
static int
read_realms_entry(void *closure, int fc, char **fv, grad_locus_t *loc)
{
	struct _parse_data *pd = closure;
        grad_realm_t *rp;
	int i;
	
        if (fc < 2) {
                grad_log_loc(GRAD_LOG_ERR, loc, _("too few fields (%d)"), fc);
                return -1;
        }

        pd->loc = loc;
	
        rp = grad_emalloc(sizeof(grad_realm_t));
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
			grad_log_loc(GRAD_LOG_NOTICE, loc, _("discarding entry"));
			grad_client_destroy_queue(rp->queue);
			grad_free(rp);
			return 0;
		}
	}

        GRAD_STRING_COPY(rp->realm, fv[0]);
        
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
	grad_realm_t *r = item;
	grad_client_destroy_queue(r->queue);
	grad_envar_free_list(&r->args);
	grad_free(item);
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
	pd.ports[GRAD_PORT_AUTH] = auth_port;
	pd.ports[GRAD_PORT_ACCT] = acct_port;
        return grad_read_raddb_file(file, 1, NULL, read_realms_entry, &pd);
}

/* Realm Lookup Functions */

static int
realm_match_name_p(const grad_realm_t *realm, const char *name)
{
	return (grad_envar_lookup_int(realm->args, "ignorecase", 0) ?
		grad_c_strcasecmp : strcmp) (realm->realm, name) == 0;
}

/* Find a realm in the REALM list */
grad_realm_t *
grad_realm_lookup_name(char *realm)
{
        grad_realm_t *p;
	grad_iterator_t *itr = grad_iterator_create(realms);

	if (!itr)
		return NULL;

        for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr))
		if (realm_match_name_p(p, realm))
                        break;
	
        if (!p && strcmp(realm, "NOREALM")) {
        	for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr))
                        if (strcmp(p->realm, "DEFAULT") == 0)
                                break;
        }
        grad_iterator_destroy(&itr);
        return p;
}

int
grad_realm_verify_ip(grad_realm_t *realm, grad_uint32_t ip)
{
	grad_server_t *serv;
	grad_iterator_t *itr;

	if (!realm->queue
	    || (itr = grad_iterator_create(realm->queue->servers)) == NULL)
		return 0;
	for (serv = grad_iterator_first(itr); serv; serv = grad_iterator_next(itr))
	     	if (serv->addr == ip)
			break;
	grad_iterator_destroy(&itr);
	return serv != NULL;
}

grad_realm_t *
grad_realm_lookup_ip(grad_uint32_t ip)
{
	grad_realm_t *p;
	grad_iterator_t *itr;

        if (!(itr = grad_iterator_create(realms)))
	    return NULL;
        for (p = grad_iterator_first(itr); p; p = grad_iterator_next(itr))
		if (grad_realm_verify_ip(p, ip))
			break;
	grad_iterator_destroy(&itr);
	return p;
}

int
grad_realm_strip_p(grad_realm_t *r)
{
	return grad_envar_lookup_int(r->args, "strip", 1);
}

size_t
grad_realm_get_quota(grad_realm_t *r)
{
	return grad_envar_lookup_int(r->args, "quota", 0);
}
		
