/* This file is part of GNU RADIUS.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef USE_DBM

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <raddbm.h>

#ifdef NDBM

int
open_dbm(name, dbmfile)
	char *name;
	DBM_FILE *dbmfile;
{
	return (*dbmfile = dbm_open(name, O_RDONLY, 0)) == NULL;
}

int
create_dbm(name, dbmfile)
	char *name;
	DBM_FILE *dbmfile;
{
	return (*dbmfile = dbm_open(name, O_RDWR|O_CREAT|O_TRUNC, 0600))
		== NULL;
}

int
close_dbm(dbmfile)
	DBM_FILE dbmfile;
{
	dbm_close(dbmfile);
}

int
fetch_dbm(dbmfile, key, ret)
	DBM_FILE dbmfile;
	DBM_DATUM key;
	DBM_DATUM *ret;
{
	*ret = dbm_fetch(dbmfile, key);
	return ret->dptr == NULL;
}

int
insert_dbm(dbmfile, key, contents)
	DBM_FILE dbmfile;
	DBM_DATUM key;
	DBM_DATUM contents;
{
	return dbm_store(dbmfile, key, contents, DBM_INSERT);
}

#else

/*ARGSUSED*/
int
open_dbm(name, dbmfile)
	char *name;
	DBM_FILE *dbmfile;
{
	return dbminit(name);
}

int
create_dbm(name, dbmfile)
	char *name;
	DBM_FILE *dbmfile;
{
	int fd;
	char *p;

	p = mkfilename(name, ".pag");
	fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	efree(p);
	if (fd < 0) 
		return 1;
	close(fd);

	p = mkfilename(name, ".dir");
	fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	efree(p);
	if (fd < 0) 
		return 1;
	close(fd);
	return dbminit(name);
}

/*ARGSUSED*/
int
close_dbm(dbmfile)
	DBM_FILE dbmfile;
{
	dbmclose();
}

/*ARGSUSED*/
int
fetch_dbm(dbmfile, key, ret)
	DBM_FILE dbmfile;
	DBM_DATUM key;
	DBM_DATUM *ret;
{
	*ret = fetch(key);
	return ret->dptr == NULL;
}

int
insert_dbm(dbmfile, key, contents)
	DBM_FILE dbmfile;
	DBM_DATUM key;
	DBM_DATUM contents;
{
	return store(key, contents);
}

#endif

#endif
