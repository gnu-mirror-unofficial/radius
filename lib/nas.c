/* This file is part of GNU RADIUS.
   Copyright (C) 2001, Free Software Foundation
  
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
#include <checkrad.h>

static NAS  *naslist;      /* raddb/naslist */

static void nas_free_list(NAS *cl);
static int read_naslist_entry();

/* ****************************************************************************
 * raddb/naslist
 */

/* Free a NAS list */
void
nas_free_list(list)
        NAS *list;
{
        NAS *next;

        while (list) {
                next = list->next;
                envar_free_list(list->args);
                free_entry(list);
                list = next;
        }
}

/*
 * parser
 */
/*ARGSUSED*/
int
read_naslist_entry(unused, fc, fv, file, lineno)
        void *unused;
        int fc;
        char **fv;
        char *file;
        int lineno;
{
        NAS nas, *nasp;

        if (fc < 2) {
                radlog(L_ERR, "%s:%d: %s", file, lineno, _("too few fields"));
                return -1;
        }

        bzero(&nas, sizeof(nas));
        STRING_COPY(nas.shortname, fv[1]);
	if (fv[2][0] == 0)
		STRING_COPY(nas.nastype, "true");
	else
		STRING_COPY(nas.nastype, fv[2]);
        if (strcmp(fv[0], "DEFAULT") == 0) {
                nas.ipaddr = 0;
                STRING_COPY(nas.longname, fv[0]);
        } else {
                nas.ipaddr = ip_gethostaddr(fv[0]);
                ip_gethostname(nas.ipaddr, nas.longname, sizeof(nas.longname));
        }
        if (fc >= 4)
                nas.args = envar_parse_argcv(fc-3, &fv[3]);
        
        nasp = Alloc_entry(NAS);

        memcpy(nasp, &nas, sizeof(nas));

        nasp->next = naslist;
        naslist = nasp;
        
        return 0;
}

/*
 * Read naslist file
 */
int
nas_read_file(file)
        char *file;
{
        nas_free_list(naslist);
        naslist = NULL;

        return read_raddb_file(file, 1, read_naslist_entry, NULL);
}

/*
 * NAS lookup functions:
 */

NAS *
nas_lookup_name(name)
        char *name;
{
        NAS *nas;
        NAS *defnas = NULL;
        
        for (nas = naslist; nas; nas = nas->next) {
                if (nas->ipaddr == 0)
                        defnas = nas;
                else if (strcmp(nas->shortname, name) == 0
                         || strcmp(nas->longname, name) == 0)
                        break;
        }
        return nas ? nas : defnas;
}

/* Find a nas in the NAS list */
NAS *
nas_lookup_ip(ipaddr)
        UINT4 ipaddr;
{
        NAS *nas;
        NAS *defnas = NULL;
        
        for (nas = naslist; nas; nas = nas->next) {
                if (nas->ipaddr == 0) 
                        defnas = nas;
                else if (nas->ipaddr == ipaddr)
                        break;
        }
        return nas ? nas : defnas;
}


/* Find the name of a nas (prefer short name) */
char *
nas_ip_to_name(ipaddr, buf, size)
        UINT4 ipaddr;
        char *buf;
        size_t size;
{
        NAS *nas;
        
        if ((nas = nas_lookup_ip(ipaddr)) != NULL) {
                if (nas->shortname[0])
                        return nas->shortname;
                else
                        return nas->longname;
        }
        return ip_gethostname(ipaddr, buf, size);
}

/* Find the name of a nas (prefer short name) based on the request */
NAS *
nas_request_to_nas(radreq)
        RADIUS_REQ *radreq;
{
        UINT4 ipaddr;
        VALUE_PAIR *pair;

        if ((pair = avl_find(radreq->request, DA_NAS_IP_ADDRESS)) != NULL)
                ipaddr = pair->lvalue;
        else
                ipaddr = radreq->ipaddr;

        return nas_lookup_ip(ipaddr);
}

char *
nas_request_to_name(radreq, buf, size)
        RADIUS_REQ *radreq;
        char *buf;
        size_t size;
{
        UINT4 ipaddr;
        NAS *nas;
        VALUE_PAIR *pair;

        if ((pair = avl_find(radreq->request, DA_NAS_IP_ADDRESS)) != NULL)
                ipaddr = pair->lvalue;
        else
                ipaddr = radreq->ipaddr;

        if ((nas = nas_lookup_ip(ipaddr)) != NULL) {
                if (nas->shortname[0])
                        return nas->shortname;
                else
                        return nas->longname;
        }
        return ip_gethostname(ipaddr, buf, size);
}

NAS *
nas_next(p)
        NAS *p;
{
        if (!p)
                return naslist;
        return p->next;
}
        
