/* This file is part of GNU Radius.
   Copyright (C) 2002, 2003 Free Software Foundation
  
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

static LIST /* of REALM */ *realms; 

struct _parse_data {
	int (*fun)();
	int ports[PORT_MAX];
	char *file;
	int line;
};

int
_parse_server(int argc, char **argv, struct _parse_data *pd, int *np,
	      RADIUS_SERVER *srv)
{
	memset(srv, 0, sizeof(*srv));
	srv->name = argv[*np];
	srv->addr = ip_gethostaddr(argv[(*np)++]);
	if (*np+1 < argc && argv[*np][0] == ':') {
		char *p;
		
                srv->port[PORT_AUTH] = strtoul(argv[++*np], &p, 0);
		if (++*np+1 < argc && argv[*np][0] == ':') {
			srv->port[PORT_ACCT] = strtoul(argv[++*np], &p, 0);
		} else
			srv->port[PORT_ACCT] = srv->port[PORT_AUTH] + 1;
		++*np;
	} else {
		srv->port[PORT_AUTH] = pd->ports[PORT_AUTH];
		srv->port[PORT_ACCT] = pd->ports[PORT_ACCT];
	}
	if (pd->fun && pd->fun(srv)) {
		radlog(L_ERR,
		       "%s:%d: can't find secret for %s",
		       pd->file, pd->line, srv->name);
		return 1; 
	}
	return 0;
}

int
_parse_server_list(RADIUS_SERVER_QUEUE *qp, char *str, struct _parse_data *pd)
{
	int i, argc;
	char **argv;

	if (argcv_get(str, ",:", &argc, &argv)) 
		return 1;

	for (i = 0; i < argc; i++) {
		RADIUS_SERVER srv;
		if (_parse_server(argc, argv, pd, &i, &srv) == 0) 
			rad_clt_append_server(qp, rad_clt_alloc_server(&srv));

		if (i < argc && argv[i][0] != ',') {
			radlog(L_ERR,
			       _("%s:%d: expected , but found %s"),
			       pd->file, pd->line, argv[i]);
			argcv_free(argc, argv);
			return 1;
		}
	}
	argcv_free(argc, argv);
	return 0;
}


/* read realms entry */
/*ARGSUSED*/
int
read_realms_entry(struct _parse_data *pd, int fc, char **fv,
		  char *file,int lineno)
{
        REALM *rp;
	int i;
	
        if (fc < 2) {
                radlog(L_ERR, _("%s:%d: too few fields (%d)"),
                       file, lineno, fc);
                return -1;
        }

        pd->file = file;
	pd->line = lineno;
	
        rp = emalloc(sizeof(REALM));
	rp->queue = NULL;
        if (strcmp(fv[1], "LOCAL") == 0) {
		i = 2;
	} else {
		rp->queue = rad_clt_create_queue(0, 0, 0);
		i = 0;
		do {
			if (_parse_server_list(rp->queue, fv[++i], pd)) {
				rad_clt_clear_server_list(rp->queue);
				break;
			}
		} while (fv[i][strlen(fv[i])-1] == ',') ;
		i++;
		
		if (list_count(rp->queue->servers) == 0) {
			radlog(L_ERR,
			       "%s:%d: cannot parse",
			       file, lineno);
			rad_clt_destroy_queue(rp->queue);
			mem_free(rp);
			return 0;
		}
	}

        STRING_COPY(rp->realm, fv[0]);
        
        if (i < fc) {
                envar_t *args;
                int n;
                
                args = envar_parse_argcv(fc-i, &fv[i]);

                rp->striprealm = envar_lookup_int(args, "strip", 1);
                n = envar_lookup_int(args, "quota", 0);
                if (n)
                        rp->maxlogins = n;
		if (rp->queue) {
			rp->queue->timeout = envar_lookup_int(args,
							      "timeout", 1);
			rp->queue->retries = envar_lookup_int(args,
							      "retries", 1);
		}
                envar_free_list(&args);
        }
	if (!realms)
		realms = list_create();
        list_prepend(realms, rp);
        return 0;
}

static int
_realm_mem_free(void *item, void *data ARG_UNUSED)
{
	REALM *r = item;
	rad_clt_destroy_queue(r->queue);
	efree(item);
	return 0;
}
	
/*
 * Read the realms file.
 */
int
realm_read_file(char *file, int auth_port, int acct_port, int (*set_secret)())
{
	struct _parse_data pd;

	list_destroy(&realms, _realm_mem_free, NULL);
        realms = NULL;
	pd.fun = set_secret;
	pd.ports[PORT_AUTH] = auth_port;
	pd.ports[PORT_ACCT] = acct_port;
        return read_raddb_file(file, 1, read_realms_entry, &pd);
}

/*
 * Realm Lookup Functions */

/* Find a realm in the REALM list */
REALM *
realm_lookup_name(char *realm)
{
        REALM *p;

        for (p = list_first(realms); p; p = list_next(realms))
                if (strcmp(p->realm, realm) == 0)
                        break;
        if (!p && strcmp(realm, "NOREALM")) {
		for (p = list_first(realms); p; p = list_next(realms))
                        if (strcmp(p->realm, "DEFAULT") == 0)
                                break;
        }
        return p;
}

int
realm_verify_ip(REALM *realm, UINT4 ip)
{
	RADIUS_SERVER *serv;
	
	if (!realm->queue)
		return 0;
	for (serv = list_first(realm->queue->servers);
	     serv;
	     serv = list_next(realm->queue->servers))
	     if (serv->addr == ip)
		     return 1;
	return 0;
}

REALM *
realm_lookup_ip(UINT4 ip)
{
	REALM *p;

        for (p = list_first(realms); p; p = list_next(realms))
		if (realm_verify_ip(p, ip))
			break;
	return p;
}

