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

/*
 * parser
 */

/* read realms entry */
/*ARGSUSED*/
int
read_realms_entry(unused, fc, fv, file, lineno)
        void *unused;
        int fc;
        char **fv;
        char *file;
        int lineno;
{
        REALM *rp;
        char *p;

        if (fc < 2) {
                radlog(L_ERR, _("%s:%d: too few fields (%d)"),
                       file, lineno, fc);
                return -1;
        }
        
        rp = Alloc_entry(REALM);

        if ((p = strchr(fv[1], ':')) != NULL) {
                *p++ = 0;
                rp->auth_port = strtoul(p, &p, 0);
                rp->acct_port = rp->auth_port + 1;
                if (*p) {
                        if (*p == ':')
                                rp->acct_port = strtoul(p+1, &p, 0);
                        else 
                                radlog(L_ERR,
                                       "%s:%d: junk after port number",
                                       file, lineno);
                }
        } else {
		int *ports = (int*) unused;
                rp->auth_port = ports[0];
                rp->acct_port = ports[1];
        }
        if (strcmp(fv[1], "LOCAL") != 0)
                rp->ipaddr = ip_gethostaddr(fv[1]);
        STRING_COPY(rp->realm, fv[0]);
        STRING_COPY(rp->server, fv[1]);
        
        if (fc > 3 && isdigit(fv[fc-1][0])) {
                /* Compatibility quirk: set login quota and decrease the
                   number of fields. */
                rp->maxlogins = atoi(fv[fc-1]);
                fc--;
        }
        
        if (fc > 2) {
                envar_t *args;
                int n;
                
                args = envar_parse_argcv(fc-2, &fv[2]);

                rp->striprealm = envar_lookup_int(args, "strip", 1);
                n = envar_lookup_int(args, "quota", 0);
                if (n)
                        rp->maxlogins = n;
                envar_free_list(args);
        }
        rp->next = realms;
        realms = rp;
        return 0;
}

/*
 * Read the realms file.
 */
int
realm_read_file(file, auth_port, acct_port)
        char *file;
	int auth_port;
	int acct_port;
{
	int ports[2];
        free_slist((struct slist*)realms, NULL);
        realms = NULL;
	ports[0] = auth_port;
	ports[1] = acct_port;
        return read_raddb_file(file, 1, read_realms_entry, ports);
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

REALM *
realm_lookup_ip(ip)
	UINT4 ip;
{
	REALM *p;

	for (p = realms; p; p = p->next)
		if (p->ipaddr == ip)
			break;
	return p;
}
