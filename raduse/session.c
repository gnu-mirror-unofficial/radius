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

#define SERVER
#include <raduse.h>

#define DEBUG(c)

SNMP_GET_TAB *snmp_get_lookup(SNMP_GET_TAB *tab, oid_t oid);

/* return formatted textual description of SNMP error status */
char *
format_snmp_error_str(err_stat)
        int err_stat;
{
        switch (err_stat) {
        case SNMP_ERR_TOOBIG:
                return "packet too big";
        case SNMP_ERR_NOSUCHNAME:
                return "no such variable";
        case SNMP_ERR_BADVALUE:
                return "bad value";
        case SNMP_ERR_READONLY:
                return "variable read only";
        case SNMP_ERR_GENERR:
                return "general error";
        case SNMP_ERR_NOACCESS:
                return "variable is not accessible";
        case SNMP_ERR_WRONGTYPE:
                return "bad type for the variable";
        case SNMP_ERR_WRONGLENGTH:
                return "wrong length";
        case SNMP_ERR_WRONGENCODING:
                return "wrong encoding";
        case SNMP_ERR_WRONGVALUE:
                return "wrong value";
        case SNMP_ERR_NOCREATION:
                return "can't create";
        case SNMP_ERR_INCONSISTENTVALUE:
                return "value inconsistent";
        case SNMP_ERR_RESOURCEUNAVAILABLE:
                return "resource unavailable";
        case SNMP_ERR_COMMITFAILED:
                return "commit falied";
        case SNMP_ERR_UNDOFAILED:
                return "undo failed";
        case SNMP_ERR_AUTHORIZATIONERROR:
                return "auth failed";
        case SNMP_ERR_NOTWRITABLE:
                return "variable not writable";
        case SNMP_ERR_INCONSISTENTNAME:
                return "name inconsistent";
        }
        return "no error";
}

void
process_var(var, ptr)
        struct snmp_var *var;
        void *ptr;
{
        char **sptr;
        oid_t *oidptr;
        struct timeval *tvptr;
        struct in_addr in;
        char buf[512];

        DEBUG(("%s = ",
               sprint_oid(buf, sizeof(buf), var->name)));
                
        switch (var->type) {
        case SMI_STRING:
                sptr = (char**)ptr;
                if (*sptr)
                        efree(*sptr);
                *sptr = estrdup(var->var_str);
                DEBUG(("\"%s\"", var->var_str));
                break;
        case SMI_TIMETICKS:
                tvptr = (struct timeval*)ptr;
                tvptr->tv_sec = var->var_int / 100;
                tvptr->tv_usec = (var->var_int - tvptr->tv_sec*100)*10000;
                DEBUG(("%s", format_time(tvptr, buf, sizeof buf)));
                break;
        case SMI_INTEGER:
                *(unsigned*)ptr = var->var_int;
                DEBUG(("%d", var->var_int));
                break;
        case SMI_COUNTER32:
                *(counter*)ptr = var->var_int;
                DEBUG(("%d", var->var_int));
                break;
        case SMI_COUNTER64:
                break;
        case SMI_IPADDRESS:
                *(UINT4*)ptr = *(unsigned int*)var->var_str;
                DEBUG(("%s", ip_iptostr(ntohl(*(UINT4*)ptr), buf)));
                break;
        case SMI_OPAQUE:
                sptr = (char**)ptr;
                if (*sptr)
                        efree(*sptr);
                *sptr = emalloc(var->val_length);
                memcpy(*sptr, var->var_str, var->val_length);
                break;
        case SMI_OBJID:
                oidptr = (oid_t*)ptr;
                if (*oidptr)
                        efree(*oidptr);
                *oidptr = oid_dup(var->var_oid);
                DEBUG(("%s", sprint_oid(buf, sizeof(buf), var->var_oid)));
                break;
        }
        DEBUG(("\n"));
}

int
converse(type, sp, pdu, closure)
        int type;
        struct snmp_session *sp;
        struct snmp_pdu *pdu;
        void *closure;
{
        struct snmp_var *var;
        int ind;
        SNMP_GET_TAB *tab;
        char ipbuf[DOTTED_QUAD_LEN];
        
        if (type == SNMP_CONV_TIMEOUT) {
                radlog(L_ERR, "timed out in waiting SNMP response from %s\n",
                       ip_iptostr(sp->remote_sin.sin_addr.s_addr, ipbuf));
                /*FIXME: inform main that the timeout has occured */
                return 1;
        }

        if (type != SNMP_CONV_RECV_MSG)
                return 1;

        if (pdu->err_stat != SNMP_ERR_NOERROR) 
                printf("Error in packet: %s\n",
                       format_snmp_error_str(pdu->err_stat));
        
        for (var = pdu->var, ind = 1; var; var = var->next, ind++) {
                if (ind == pdu->err_ind) {
                        char oidbuf[512];
                        
                        printf("this variable caused error: %s\n",
                               sprint_oid(oidbuf, sizeof oidbuf, var->name));
                        break;
                }

                tab = snmp_get_lookup(closure, var->name);
                if (tab) 
                        process_var(var, tab->closure);
        }
                                                
        return 1;
}

SNMP_GET_TAB *
snmp_get_lookup(tab, oid)
        SNMP_GET_TAB *tab;
        oid_t oid;
{
        for (; tab->oid; tab++)
                if (oid_cmp(tab->oid, oid) == 0)
                        return tab;
        return NULL;
}

SNMP_WALK_TAB *
snmp_walk_lookup(tab, oid)
        SNMP_WALK_TAB *tab;
        oid_t oid;
{
        for (; tab->oid; tab++)
                if (memcmp(OIDPTR(tab->oid), OIDPTR(oid),
                           (OIDLEN(tab->oid)-1)*sizeof(tab->oid[0])) == 0)
                        return tab;
        return NULL;
}

void
run_query(tab)
        SNMP_GET_TAB *tab;
{
        int i;
        struct snmp_session *session;
        struct snmp_pdu *pdu;
        struct snmp_var *var;
        
        session = snmp_session_create(community, hostname, port, converse, tab);
        if (!session) {
                radlog(L_CRIT, "(session) snmp err %d\n", snmp_errno);
                exit(1);
        }

        pdu = snmp_pdu_create(SNMP_PDU_GET);
        if (!pdu) {
                radlog(L_ERR, "(pdu) snmp err %d\n", snmp_errno);
                return;
        }
        
        for (; tab->oid; tab++) {
                var = snmp_var_create(tab->oid);
                if (!var) {
                        radlog(L_ERR, "(var) snmp err %d\n", snmp_errno);
                        continue;
                }
                snmp_pdu_add_var(pdu, var);
        }

        if (snmp_query(session, pdu)) {
                radlog(L_ERR, "(snmp_query) snmp err %d\n", snmp_errno);
                return;
        }
        snmp_session_close(session);
}

struct snmp_walk_data {
        SNMP_WALK_TAB *tab;
        void *app_data;
        int count;
        u_char *instance;
        struct snmp_var *varlist;
};

int
walk_converse(type, sp, pdu, closure)
        int type;
        struct snmp_session *sp;
        struct snmp_pdu *pdu;
        void *closure;
{
        struct snmp_var *var;
        int ind;
        SNMP_WALK_TAB *tab;
        struct snmp_walk_data *data = (struct snmp_walk_data *) closure;
        int err = 0;
        char ipbuf[DOTTED_QUAD_LEN];
        
        data->varlist = NULL;

        if (type == SNMP_CONV_TIMEOUT) {
                radlog(L_ERR, "timed out in waiting SNMP response from %s\n",
                       ip_iptostr(sp->remote_sin.sin_addr.s_addr, ipbuf));
                /*FIXME: inform main that the timeout has occured */
                return 1;
        }

        if (type != SNMP_CONV_RECV_MSG)
                return 1;

        if (pdu->err_stat != SNMP_ERR_NOERROR
            && pdu->err_stat != SNMP_ERR_NOSUCHNAME) {
                err++;
                printf("Error in packet: %s\n",
                       format_snmp_error_str(pdu->err_stat));
        }
        DEBUG(("processing PDU\n"));
        for (var = pdu->var, ind = 1; var; var = var->next, ind++) {
                if (ind == pdu->err_ind) {
                        char oidbuf[512];

                        if (err) {
                                printf("this variable caused error: %s\n",
                                       sprint_oid(oidbuf,
                                                  sizeof oidbuf, var->name));
                                break;
                        } else
                                continue;
                }

                tab = &data->tab[ind-1];
                if (memcmp(OIDPTR(tab->oid), OIDPTR(var->name),
                           (OIDLEN(tab->oid)-1)*sizeof(tab->oid[0])) == 0) {
                        struct snmp_var *vp;
                        data->count++;
                        process_var(var, data->instance + tab->offset);
                        vp = snmp_var_create(var->name);
                        vp->next = data->varlist;
                        data->varlist = vp;
                }
        }

        return 1;
}

void
run_walk(tab, elsize, insert, app_data)
        SNMP_WALK_TAB *tab;
        size_t elsize;
        void *(*insert)(void*,void*);
        void *app_data;
{
        struct snmp_session *session;
        struct snmp_pdu *pdu;
        struct snmp_var *var;
        struct snmp_walk_data data;

        data.tab = tab;
        data.app_data = app_data;
        data.instance = emalloc(elsize);
        data.varlist = NULL;
        session = snmp_session_create(community, hostname, port,
                                      walk_converse, &data);
        if (!session) {
                radlog(L_CRIT, "(session) snmp err %d\n", snmp_errno);
                exit(1);
        }


        for (; tab->oid; tab++) {
                oid_t oid = oid_create_from_subid(OIDLEN(tab->oid)-1,
                                                  OIDPTR(tab->oid));
                var = snmp_var_create(oid);
                efree(oid);
                if (!var) {
                        radlog(L_ERR, "(var) snmp err %d\n", snmp_errno);
                        continue;
                }
                var->next = data.varlist;
                data.varlist = var;
        }

        do  {
                pdu = snmp_pdu_create(SNMP_PDU_GETNEXT);
                if (!pdu) {
                        radlog(L_ERR, "(pdu) snmp err %d\n", snmp_errno);
                        return;
                }
                for (var = data.varlist; var; ) {
                        struct snmp_var *next = var->next;
                        snmp_pdu_add_var(pdu, var);
                        var = next;
                }

                data.count = 0;
                memset(data.instance, 0, elsize);
                if (snmp_query(session, pdu)) {
                        radlog(L_ERR,
                               "(snmp_query) snmp err %d\n", snmp_errno);
                        break;
                }
                if (data.count)
                        insert(app_data, data.instance);
        } while (data.varlist);
        efree(data.instance);
        snmp_session_close(session);
}

char *
format_time(tv, buffer, size)
        struct timeval *tv;
        char *buffer;
        int size;
{
        long timeticks;
        int centisecs, seconds, minutes, hours, days;

        timeticks = tv->tv_sec;
        days = timeticks / (60 * 60 * 24);
        timeticks %= (60 * 60 * 24);

        hours = timeticks / (60 * 60);
        timeticks %= (60 * 60);

        minutes = timeticks / 60;
        seconds = timeticks % 60;

        centisecs = tv->tv_usec / 10000;
        snprintf(buffer, size, "%d:%02d:%02d:%02d.%02d",
                 days, hours, minutes, seconds, centisecs);
        return buffer;
}

