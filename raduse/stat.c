/* This file is part of GNU RADIUS.
   Copyright (C) 2002, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#include <raduse.h>

char *stat_ident;
struct timeval stat_uptime;
serv_stat stat_config_reset;
counter stat_total_lines;
counter stat_lines_in_use;
counter stat_lines_idle;

Auth_server_stat auth_stat;
Acct_server_stat acct_stat;

int sess_stat_handler(struct snmp_var *var, void*);

struct mib_data mib_stat_data[] = {
	oid_StatIdent,	          &stat_ident,
	oid_StatUpTime,	          &stat_uptime,
	oid_StatConfigReset,      &stat_config_reset,
	oid_StatTotalLines,       &stat_total_lines,
	oid_StatTotalLinesInUse,  &stat_lines_in_use,
	oid_StatTotalLinesIdle,   &stat_lines_idle,
	NULL, NULL
};	

struct mib_data mib_auth_data[] = {
	oid_AuthServResetTime,                    &auth_stat.reset_time,
	oid_AuthServConfigReset,                  &auth_stat.status,
	oid_AuthServTotalAccessRequests,          &auth_stat.num_access_req,
	oid_AuthServTotalInvalidRequests,         &auth_stat.num_invalid_req,
	oid_AuthServTotalDupAccessRequests,       &auth_stat.num_dup_req,
	oid_AuthServTotalAccessAccepts,           &auth_stat.num_accepts,
	oid_AuthServTotalAccessRejects,           &auth_stat.num_rejects,
	oid_AuthServTotalAccessChallenges,        &auth_stat.num_challenges,
	oid_AuthServTotalMalformedAccessRequests, &auth_stat.num_bad_req,
	                                     
	oid_AuthServTotalBadAuthenticators,       &auth_stat.num_bad_auth,
	oid_AuthServTotalPacketsDropped,          &auth_stat.num_dropped,
	oid_AuthServTotalUnknownTypes,            &auth_stat.num_unknowntypes,
	NULL, NULL
};

struct mib_data mib_acct_data[] = {
	oid_AccServResetTime,                &acct_stat.reset_time,
	oid_AccServConfigReset,              &acct_stat.status,
	oid_AccServTotalRequests,            &acct_stat.num_req,
	oid_AccServTotalInvalidRequests,     &acct_stat.num_invalid_req,
	oid_AccServTotalDupRequests,         &acct_stat.num_dup_req,
	oid_AccServTotalResponses,           &acct_stat.num_resp,
	oid_AccServTotalMalformedRequests,   &acct_stat.num_bad_req,
	oid_AccServTotalBadAuthenticators,   &acct_stat.num_bad_sign,
	oid_AccServTotalPacketsDropped,      &acct_stat.num_dropped,
	oid_AccServTotalNoRecords,           &acct_stat.num_norecords,
	oid_AccServTotalUnknownTypes,        &acct_stat.num_unknowntypes,
	NULL, NULL, 
};
	

void
test()
{
	char buf[64];
	
	run_query(mib_stat_data);
	run_query(mib_auth_data);
	printf("ident: %s\n", stat_ident);
	printf("uptime: %s\n", format_time(&stat_uptime, buf, sizeof buf));

        printf("status: %d\n", stat_config_reset);
	printf("total:  %d\n", stat_total_lines);
	printf("inuse:  %d\n", stat_lines_in_use);
	printf("idle :  %d\n", stat_lines_idle);
}

