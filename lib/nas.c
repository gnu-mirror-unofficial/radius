/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
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
#include <radius.h>
#include <checkrad.h>

static grad_list_t /* of grad_nas_t */ *naslist;      /* raddb/naslist */

/* ****************************************************************************
 * raddb/naslist
 */

/* Free a NAS list */
static int
_nas_mem_free(void *item, void *data ARG_UNUSED)
{
	grad_nas_t *p = item;
	grad_envar_free_list(&p->args);
	grad_free(p);
	return 0;
}


/*
 * parser
 */
/*ARGSUSED*/
static int
read_naslist_entry(void *unused ARG_UNUSED, int fc, char **fv, grad_locus_t *loc)
{
        grad_nas_t nas, *nasp;

        if (fc < 2) {
                grad_log_loc(L_ERR, loc, "%s", _("too few fields"));
                return -1;
        }

        memset(&nas, 0, sizeof(nas));
        STRING_COPY(nas.shortname, fv[1]);
	if (!fv[2])
		STRING_COPY(nas.nastype, "true");
	else
		STRING_COPY(nas.nastype, fv[2]);
        if (strcmp(fv[0], "DEFAULT") == 0) {
                nas.netdef.ipaddr = nas.netdef.netmask = 0;
                STRING_COPY(nas.longname, fv[0]);
        } else {
		grad_ip_getnetaddr(fv[0], &nas.netdef);
		/*FIXME: Do we still need that? */
                grad_ip_gethostname(nas.netdef.ipaddr,
				    nas.longname, sizeof(nas.longname));
		if (nas.longname[0])
			STRING_COPY(nas.longname, fv[0]);
        }
        if (fc >= 4)
                nas.args = grad_envar_parse_argcv(fc-3, &fv[3]);
        
        nasp = grad_emalloc(sizeof(grad_nas_t));
	
        memcpy(nasp, &nas, sizeof(nas));
	if (!naslist)
		naslist = grad_list_create();
	grad_list_prepend(naslist, nasp);
        return 0;
}

/*
 * Read naslist file
 */
int
grad_nas_read_file(char *file)
{
	grad_list_destroy(&naslist, _nas_mem_free, NULL);
        return grad_read_raddb_file(file, 1, read_naslist_entry, NULL);
}

/*
 * NAS lookup functions:
 */

grad_nas_t *
grad_nas_lookup_name(char *name)
{
        grad_nas_t *nas;
        grad_nas_t *defnas = NULL;
        grad_iterator_t *itr = iterator_create(naslist);

	if (!itr)
		return NULL;
	for (nas = iterator_first(itr); nas; nas = iterator_next(itr)) {
                if (nas->netdef.ipaddr == 0 && nas->netdef.netmask == 0)
                        defnas = nas;
                else if (strcmp(nas->shortname, name) == 0
                         || strcmp(nas->longname, name) == 0)
                        break;
        }
        iterator_destroy(&itr);
        return nas ? nas : defnas;
}

/* Find a nas in the NAS list */
grad_nas_t *
grad_nas_lookup_ip(grad_uint32_t ipaddr)
{
        grad_nas_t *nas = NULL;
        grad_iterator_t *itr = iterator_create(naslist);

	if (!itr)
		return NULL;
	for (nas = iterator_first(itr); nas; nas = iterator_next(itr)) {
                if (grad_ip_in_net_p(&nas->netdef, ipaddr))
                        break;
        }
	iterator_destroy(&itr);
        return nas;
}


/* Find the name of a nas (prefer short name) */
char *
grad_nas_ip_to_name(grad_uint32_t ipaddr, char *buf, size_t size)
{
        grad_nas_t *nas;
        
        if ((nas = grad_nas_lookup_ip(ipaddr)) != NULL) {
                if (nas->shortname[0])
                        return nas->shortname;
                else
                        return nas->longname;
        }
        return grad_ip_gethostname(ipaddr, buf, size);
}

/* Find the name of a nas (prefer short name) based on the request */
grad_nas_t *
grad_nas_request_to_nas(const grad_request_t *radreq)
{
        grad_uint32_t ipaddr;
        grad_avp_t *pair;

        if ((pair = grad_avl_find(radreq->request, DA_NAS_IP_ADDRESS)) != NULL)
                ipaddr = pair->avp_lvalue;
        else
                ipaddr = radreq->ipaddr;

        return grad_nas_lookup_ip(ipaddr);
}

char *
grad_nas_request_to_name(const grad_request_t *radreq, char *buf, size_t size)
{
        grad_uint32_t ipaddr;
        grad_nas_t *nas;
        grad_avp_t *pair;

        if ((pair = grad_avl_find(radreq->request, DA_NAS_IP_ADDRESS)) != NULL)
                ipaddr = pair->avp_lvalue;
        else
                ipaddr = radreq->ipaddr;

        if ((nas = grad_nas_lookup_ip(ipaddr)) != NULL) {
                if (nas->shortname[0])
                        return nas->shortname;
                else
                        return nas->longname;
        }
        return grad_ip_gethostname(ipaddr, buf, size);
}

grad_iterator_t *
grad_nas_iterator()
{
	return iterator_create(naslist);
}

