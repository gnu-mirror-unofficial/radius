/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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
        grad_counter_t num_req;
        grad_counter_t num_invalid_req;
        grad_counter_t num_dup_req;
        grad_counter_t num_resp;
        grad_counter_t num_bad_req;
        grad_counter_t num_bad_sign;
        grad_counter_t num_dropped;
        grad_counter_t num_norecords;
        grad_counter_t num_unknowntypes;
} Acct_server_stat;

typedef struct {
        serv_stat status;
        struct timeval reset_time;
        grad_counter_t num_access_req;
        grad_counter_t num_invalid_req;
        grad_counter_t num_dup_req;
        grad_counter_t num_accepts;
        grad_counter_t num_rejects;
        grad_counter_t num_challenges;
        grad_counter_t num_bad_req;
        grad_counter_t num_bad_auth;
        grad_counter_t num_dropped;
        grad_counter_t num_unknowntypes;
} Auth_server_stat;

struct nas_stat {
        struct nas_stat *next;
        int index;
        grad_uint32_t ipaddr;
        grad_counter_t ports_active;
        grad_counter_t ports_idle;
        Auth_server_stat auth;
        Acct_server_stat acct;
};


#endif



