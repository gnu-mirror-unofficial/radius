/* This file is part of GNU Radius.
   Copyright (C) 2001,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.
  
   GNU Radius is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. */

#ifdef USE_DBM

/* **************************************************************************
 * DBM wrappers
 */
#if USE_DBM == DBM_NDBM
# include <ndbm.h>
typedef DBM *DBM_FILE;
#else
# include <dbm.h>
typedef int DBM_FILE;
#endif

typedef datum DBM_DATUM;

int grad_dbm_open(char *name, DBM_FILE *dbmfile);
int grad_dbm_close(DBM_FILE dbmfile);
int grad_dbm_fetch(DBM_FILE dbmfile, DBM_DATUM key, DBM_DATUM *ret);

#endif
