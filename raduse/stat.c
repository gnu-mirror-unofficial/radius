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

SNMP_GET_TAB get_stat_tab[] = {
        oid_StatIdent,            &stat_ident,
        oid_StatUpTime,           &stat_uptime,
        oid_StatConfigReset,      &stat_config_reset,
        oid_StatTotalLines,       &stat_total_lines,
        oid_StatTotalLinesInUse,  &stat_lines_in_use,
        oid_StatTotalLinesIdle,   &stat_lines_idle,
        NULL, NULL
};      

SNMP_GET_TAB get_auth_tab[] = {
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

SNMP_GET_TAB mib_acct_data[] = {
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

struct nas_usage_header {
        struct nas_usage *head, *tail;
} nas_usage_header;

SNMP_WALK_TAB walk_stat_tab[] = {
        oid_NASAddress,     offsetof(struct nas_usage, ipaddr),
        oid_NASID,          offsetof(struct nas_usage, ident),
        oid_NASLinesInUse,  offsetof(struct nas_usage, ports_active),
        oid_NASLinesIdle,   offsetof(struct nas_usage, ports_idle), 
        NULL
};

struct port_usage_header {
        struct port_usage *head, *tail;
} port_usage_header;

SNMP_WALK_TAB walk_port_tab[] = {
        oid_StatPortNASIndex,
        offsetof(struct port_usage, nas_index),
        
        oid_StatPortID,
        offsetof(struct port_usage, port_no),

        oid_StatPortFramedAddress,
        offsetof(struct port_usage, framed_address),  

        oid_StatPortTotalLogins,
        offsetof(struct port_usage, count),  

        oid_StatPortStatus,
        offsetof(struct port_usage, active), 

        oid_StatPortStatusChangeTimestamp,
        offsetof(struct port_usage, start),
        
//      oid_StatPortUpTime,                offsetof(struct port_usage, ),  

        oid_StatPortLastLoginName,
        offsetof(struct port_usage, login),  

        oid_StatPortLastLoginTimestamp,
        offsetof(struct port_usage, lastin),

        oid_StatPortLastLogoutTimestamp,
        offsetof(struct port_usage, lastout),  

        oid_StatPortIdleTotalTime,
        offsetof(struct port_usage, idle),  

        oid_StatPortIdleMaxTime,
        offsetof(struct port_usage, maxidle.duration), 

        oid_StatPortIdleMaxTimestamp,
        offsetof(struct port_usage, maxidle.start),  
        
        oid_StatPortInUseTotalTime,
        offsetof(struct port_usage, inuse),  

        oid_StatPortInUseMaxTime,
        offsetof(struct port_usage, maxinuse.duration), 

        oid_StatPortInUseMaxTimestamp,
        offsetof(struct port_usage, maxinuse.start),  

        NULL
};

void *
nas_usage_insert(hdr, usg)
        struct nas_usage_header *hdr;
        struct nas_usage *usg;
{
        struct nas_usage *ptr = emalloc(sizeof(*ptr));
        memcpy(ptr, usg, sizeof(*ptr));
        ptr->next = NULL;
        if (!hdr->head)
                hdr->head = ptr;
        else
                hdr->tail->next = ptr;
        hdr->tail = ptr;
        return ptr;
}

int
portcmp(a,b)
        struct port_usage *a,*b;
{
        if (a->nas_index != b->nas_index)
                return a->nas_index - b->nas_index;
        return a->port_no - b->port_no;
}

void
portcopy(dst, src)
        struct port_usage *dst, *src;
{
        struct port_usage *next;
        if (dst->login)
                efree(dst->login);
        next = dst->next;
        memcpy(dst, src, sizeof(*dst));
        dst->next = next;
}

void *
port_usage_insert(hdr, data)
        struct port_usage_header *hdr;
        struct port_usage *data;
{
        struct port_usage *ptr, *prev = NULL;
        int rc;
        
        for (ptr = hdr->head; ptr; ptr = ptr->next) {
                rc = portcmp(data, ptr);
                if (rc == 0) {
                        break;
                } else if (rc < 0) {
                        ptr = NULL;
                        break;
                }
                prev = ptr;
        }
        if (!ptr) {
                ptr = emalloc(sizeof(*ptr));
                if (!prev) {
                        ptr->next = hdr->head;
                        hdr->head = ptr;
                } else {
                        ptr->next = prev->next;
                        prev->next = ptr;
                }
        }
        portcopy(ptr, data);
        return ptr;
}

void
test()
{
        char buf[64];
        struct nas_usage *nasp;
        struct port_usage *port;
        char ipbuf[DOTTED_QUAD_LEN];
                
        run_query(get_stat_tab);
        run_query(get_auth_tab);

        run_walk(walk_stat_tab, sizeof(struct nas_usage),
                 nas_usage_insert, &nas_usage_header);
        run_walk(walk_port_tab, sizeof(struct port_usage),
                 port_usage_insert, &port_usage_header);
        
        printf("ident: %s\n", stat_ident);
        printf("uptime: %s\n", format_time(&stat_uptime, buf, sizeof buf));

        printf("status: %d\n", stat_config_reset);
        printf("total:  %d\n", stat_total_lines);
        printf("inuse:  %d\n", stat_lines_in_use);
        printf("idle :  %d\n", stat_lines_idle);

        printf("NAS status:\n");
        for (nasp = nas_usage_header.head; nasp; nasp = nasp->next) {
                
                printf("  ident:  %s\n", nasp->ident);
                printf("  IP:     %s\n",
                       ip_iptostr(ntohl(nasp->ipaddr), ipbuf));
                printf("  active: %d\n", nasp->ports_active);
                printf("  idle:   %d\n", nasp->ports_idle);
        }
        printf("\nPort stat:\n");
        for (port = port_usage_header.head; port; port = port->next) {
                printf("  index:  %d\n", port->nas_index);  
                printf("  portno: %d\n", port->port_no);
                printf("  addr:   %s\n",
                       ip_iptostr(ntohl(port->framed_address), ipbuf));
                printf("  total logins: %d\n", port->count);
                printf("  state: %d\n", port->active);
                printf("  change: %s", ctime(&port->start));
                printf("  last login at %s", ctime(&port->lastin));
                printf("  last logout at %s", ctime(&port->lastout));
                printf("  login: %s\n", port->login);
                printf("  idle total: %s\n",
                       format_time(&port->idle, buf, sizeof buf));
                printf("  idle max: %s\n",
                       format_time(&port->maxidle.duration, buf, sizeof buf));
                printf("       at: %s", ctime(&port->maxidle.start));
                printf("  inuse total: %s\n",
                       format_time(&port->inuse, buf, sizeof buf));
                printf("  inuse max: %s\n",
                      format_time(&port->maxinuse.duration, buf, sizeof buf));
                printf("       at: %s", ctime(&port->maxinuse.start));
                printf("\n");
        }
}

