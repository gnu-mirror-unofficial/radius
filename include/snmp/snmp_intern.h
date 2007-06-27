/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001,2007 Free Software Foundation, Inc.
   Written by Sergey Poznyakoff

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

struct snmp_def {
        int req_id;
        int retries;
        int timeout;
} ;

extern struct snmp_def snmp_def;
extern snmp_alloc_t __snmp_alloc_fp;
extern snmp_free_t  __snmp_free_fp;

void snmp_request_free(struct snmp_request *req);
void snmp_request_free_list(struct snmp_request *req);
int snmp_request_xmit(struct snmp_session *sess, struct snmp_request *req);
int snmp_fdset (struct snmp_session *sp, fd_set *fdset);

