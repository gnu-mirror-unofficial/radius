/* This file is part of GNU RADIUS.
   Copyright (C) 2002, Free Software Foundation
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <radius.h>
#include <envar.h>

static REALM *realms; 

struct _parse_data {
	int (*fun)();
	int ports[PORT_MAX];
	char *file;
	int line;
};

int
_parse_server(argc, argv, pd, np, srv)
	int argc;
	char **argv;
	struct _parse_data *pd;
	int *np;
	RADIUS_SERVER *srv;
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
_parse_server_list(srvlist, str, pd)
	RADIUS_SERVER **srvlist;
	char *str;
	struct _parse_data *pd;
{
	int i, argc;
	char **argv;

	if (argcv_get(str, ",:", &argc, &argv)) 
		return 1;

	for (i = 0; i < argc; i++) {
		RADIUS_SERVER srv;
		if (_parse_server(argc, argv, pd, &i, &srv) == 0) 
			*srvlist = rad_clt_append_server(*srvlist,
					      rad_clt_alloc_server(&srv));

		if (i < argc && argv[i][0] != ',') {
			radlog(L_ERR,
			       "%s:%d: expected , but found %s",
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
read_realms_entry(pd, fc, fv, file, lineno)
        struct _parse_data *pd;
        int fc;
        char **fv;
        char *file;
        int lineno;
{
        REALM *rp;
        char *p;
	RADIUS_SERVER srv;
	int i;
	
        if (fc < 2) {
                radlog(L_ERR, _("%s:%d: too few fields (%d)"),
                       file, lineno, fc);
                return -1;
        }

        pd->file = file;
	pd->line = lineno;
	
        rp = Alloc_entry(REALM);
	rp->queue = NULL;
        if (strcmp(fv[1], "LOCAL") == 0) {
		i = 2;
	} else {
		RADIUS_SERVER *server = NULL;
		i = 0;
		do {
			if (_parse_server_list(&server, fv[++i], pd)) {
				rad_clt_clear_server_list(server);
				server = NULL;
				break;
			}
		} while (fv[i][strlen(fv[i])-1] == ',') ;
		i++;
		
		if (!server) {
			radlog(L_ERR,
			       "%s:%d: cannot parse",
			       file, lineno);
			free_entry(rp);
			return 0;
		}
		rp->queue = rad_clt_create_queue(0, 0, 0);
		rp->queue->first_server = server;
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
                envar_free_list(args);
        }
        rp->next = realms;
        realms = rp;
        return 0;
}

static void
_realm_free_entry(r)
	REALM *r;
{
	rad_clt_destroy_queue(r->queue);
}
	
/*
 * Read the realms file.
 */
int
realm_read_file(file, auth_port, acct_port, set_secret)
        char *file;
	int auth_port;
	int acct_port;
	int (*set_secret)();
{
	struct _parse_data pd;
	
        free_slist((struct slist*)realms, _realm_free_entry);
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
realm_lookup_name(realm)
        char *realm;
{
        REALM *p;

        for (p = realms; p; p = p->next)
                if (strcmp(p->realm, realm) == 0)
                        break;
        if (!p && strcmp(realm, "NOREALM")) {
                for (p = realms; p; p = p->next)
                        if (strcmp(p->realm, "DEFAULT") == 0)
                                break;
        }
        return p;
}

int
realm_verify_ip(realm, ip)
	REALM *realm;
	UINT4 ip;
{
	RADIUS_SERVER *serv;
	
	if (!realm->queue)
		return 0;
	for (serv = realm->queue->first_server; serv;  serv = serv->next)
		if (serv->addr == ip)
			return 1;
	return 0;
}

REALM *
realm_lookup_ip(ip)
	UINT4 ip;
{
	REALM *p;

	for (p = realms; p; p = p->next)
		if (realm_verify_ip(p, ip))
			break;
	return p;
}

void
realm_iterate(fun)
	int (*fun)();
{
	REALM *p;

	for (p = realms; p; p = p->next)
		fun(p);
}
