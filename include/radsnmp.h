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

#ifndef __radsnmp_h
#define __radsnmp_h

typedef enum {
        serv_other=1,
        serv_reset,
        serv_init,
        serv_running,
        serv_suspended,
        serv_shutdown
} serv_stat;

typedef struct {
        serv_stat status;
        struct timeval reset_time;
        counter num_req;
        counter num_invalid_req;
        counter num_dup_req;
        counter num_resp;
        counter num_bad_req;
        counter num_bad_sign;
        counter num_dropped;
        counter num_norecords;
        counter num_unknowntypes;
} Acct_server_stat;

typedef struct {
        serv_stat status;
        struct timeval reset_time;
        counter num_access_req;
        counter num_invalid_req;
        counter num_dup_req;
        counter num_accepts;
        counter num_rejects;
        counter num_challenges;
        counter num_bad_req;
        counter num_bad_auth;
        counter num_dropped;
        counter num_unknowntypes;
} Auth_server_stat;

struct nas_stat {
        struct nas_stat *next;
        int index;
        UINT4 ipaddr;
        counter ports_active;
        counter ports_idle;
        Auth_server_stat auth;
        Acct_server_stat acct;
};


#endif



