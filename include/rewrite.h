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
/*
 * Data types
 */
typedef enum {
        Undefined,
        Integer,
        String,
        Max_datatype
} Datatype;

typedef union {
        int       ival;
        char      *sval;
} Datum;

void rewrite_init();
int interpret(char *fcall, RADIUS_REQ *req, Datatype *type, Datum *datum);
int rewrite_stmt_term(int finish, void *block_data, void *handler_data);

#ifdef RADIUS_SERVER_GUILE
SCM radscm_datum_to_scm(Datatype type, Datum datum);
int radscm_scm_to_ival(SCM cell, int *val);
SCM radscm_rewrite_execute(const char *func_name, SCM ARGS);
#endif
