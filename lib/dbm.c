/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#ifdef USE_DBM

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <raddbm.h>

#if USE_DBM == DBM_NDBM

int
open_dbm(char *name, DBM_FILE *dbmfile)
{
        return (*dbmfile = dbm_open(name, O_RDONLY, 0)) == NULL;
}

int
create_dbm(char *name, DBM_FILE *dbmfile)
{
        return (*dbmfile = dbm_open(name, O_RDWR|O_CREAT|O_TRUNC, 0600))
                == NULL;
}

int
close_dbm(DBM_FILE dbmfile)
{
        dbm_close(dbmfile);
        return 0;
}

int
fetch_dbm(DBM_FILE dbmfile, DBM_DATUM key, DBM_DATUM *ret)
{
        *ret = dbm_fetch(dbmfile, key);
        return ret->dptr == NULL;
}

int
insert_dbm(DBM_FILE dbmfile, DBM_DATUM key, DBM_DATUM contents)
{
        return dbm_store(dbmfile, key, contents, DBM_INSERT);
}

#else /* DBM_DBM */

/*ARGSUSED*/
int
open_dbm(char *name, DBM_FILE *dbmfile)
{
        return dbminit(name);
}

int
create_dbm(char *name, DBM_FILE *dbmfile)
{
        int fd;
        char *p;

        p = emalloc(strlen(name)+5);
        strcat(strcpy(p, name), ".pag");
        fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        efree(p);
        if (fd < 0) 
                return 1;
        close(fd);

        p = emalloc(strlen(name)+5);
        strcat(strcpy(p, name), ".dir");
        fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        efree(p);
        if (fd < 0) 
                return 1;
        close(fd);
        return dbminit(name);
}

/*ARGSUSED*/
int
close_dbm(DBM_FILE dbmfile)
{
        dbmclose();
}

/*ARGSUSED*/
int
fetch_dbm(DBM_FILE dbmfile, DBM_DATUM key, DBM_DATUM *ret)
{
        *ret = fetch(key);
        return ret->dptr == NULL;
}

int
insert_dbm(DBM_FILE dbmfile, DBM_DATUM key, DBM_DATUM contents)
{
        return store(key, contents);
}

#endif

#endif
