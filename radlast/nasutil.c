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

static char rcsid[] = 
"$Id$";

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>

#include "radiusd.h"
#include "radutmp.h"
#include "log.h"

NAS *naslist;


int
read_naslist()
{
	FILE	*fp;
	char	buffer[256];
	char	hostnm[128];
	char	shortnm[32];
	char	nastype[32];
	char    *file;
	int	lineno = 0;
	NAS	*c;

	if (naslist)
		return 1;
	
	file = mkfilename(radius_dir, RADIUS_NASLIST);
	if ((fp = fopen(file, "r")) == NULL) {
		efree(file);
		radlog(L_ERR|L_PERROR, _("can't open %s"), file);
		return -1;
	}
	while (fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		nastype[0] = 0;
		if (sscanf(buffer, "%s%s%s", hostnm, shortnm, nastype) < 2) {
			radlog(L_ERR, _("%s:%d: syntax error"), file, lineno);
			continue;
		}
		c = emalloc(sizeof(*c));
		c->ipaddr = get_ipaddr(hostnm);
		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));
		c->next = naslist;
		naslist = c;
	}
	fclose(fp);
	efree(file);
	return 0;
}

NAS *
nas_find(ipaddr)
	UINT4 ipaddr;
{
	NAS *cl;

	for (cl = naslist; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}

NAS *
nas_find_by_name(name)
	char *name;
{
	NAS *cl;

	for (cl = naslist; cl; cl = cl->next)
		if (strcasecmp(name, cl->shortname) == 0)
			break;

	return cl;
}

char *
nas_name(ipaddr)
	UINT4 ipaddr;
{
	NAS *cl;

	if ((cl = nas_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}
	return ip_hostname(ipaddr);
}


