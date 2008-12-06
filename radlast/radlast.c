/* This file is part of GNU Radius.
   Copyright (C) 2000,2002,2003,2004,2005,2007,
   2008 Free Software Foundation, Inc.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <netinet/in.h>

#include <common.h>
#include <radius/radutmp.h>
#include <radius/radargp.h>

#define IP_ADDR_LEN 15

struct user_chain {
        struct user_chain *next;
        char *name;
};

typedef struct wtmp_chain WTMP;
struct wtmp_chain {
        WTMP *next;
        WTMP *prev;
        struct radutmp ut;
};      

int read_naslist();
void radwtmp();
void adduser(char*);
int want(struct radutmp *);
void add_logout(struct radutmp *bp);
void add_nas_restart(struct radutmp *bp);
WTMP *find_login(struct radutmp *bp);
WTMP *find_logout(struct radutmp *bp);
WTMP *find_restart(struct radutmp *bp);
void print_entry(WTMP *pp, struct radutmp *bp, int mark);
void print_reboot_entry(struct radutmp *bp);
void print_acct_toggle(struct radutmp *bp);
void delete_logout(WTMP *pp, struct radutmp *utp);
WTMP *add_wtmp_entry(WTMP **first, WTMP *pp);
WTMP *delete_wtmp_entry(WTMP **first, WTMP *pp);
WTMP *find_wtmp_nas(WTMP *first, struct radutmp *bp);
WTMP *find_wtmp_nas_port(WTMP *first, struct radutmp *bp);
WTMP *find_wtmp_nas_port_sid(WTMP *first, struct radutmp *bp);

grad_uint32_t host_ip = 0;
grad_netdef_t nas_ip = { 0, 0 } ;
int port = 0;
int width = 5;
int show_seconds = 0;
int mark_missing_stops = 0;
int long_fmt = 0;
int namesize = 10;
int nas_name_len = 8;

int maxrec = -1;
char *file = RADLOG_DIR "/" RADWTMP;
struct radutmp buf[1024];

char *nas_name = NULL; /* If not-null, select records matching this
                          NAS name */

/* List of users user wants to get info about */
struct user_chain *user_chain, *user_last;
/* True if user wants to see NAS reboot records */
int show_reboot_rec;
/* True if user wants to see NAS shutdown records */
int show_shutdown_rec;

/* List of logouts without logins */
WTMP *logout_list;
/* List of recent logins */
WTMP *login_list;
/* List of NAS up/down transitions */
WTMP *nas_updown_list;

const char *argp_program_version = "radlast (" PACKAGE ") " VERSION;
static char doc[] = N_("report last logins from Radius database.");

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         N_("radlast specific switches:"), 0},
        {NULL, '0', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '1', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '2', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '3', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '4', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '5', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '6', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '7', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '8', NULL, OPTION_HIDDEN, NULL, 0},
        {NULL, '9', NULL, OPTION_HIDDEN, NULL, 0},
        {"count", 'c', N_("NUMBER"), 0,
         N_("show at most NUMBER records"), 0},
        {"file", 'f', N_("FILE"), 0,
         N_("use FILE as radwtmp"), 0},
        {"host", 'h', N_("IPADDR"), 0,
         N_("show logins with IPADDR"), 0},
        {"missed-stops", 'm', NULL, 0,
         N_("mark records with missed stops with bump (!)"), 0},
        {"nas", 'n', N_("NASNAME"), 0,
         N_("show logins from given NAS"), 0},
        {"long-format", 'l', NULL, 0,
         N_("use long output format"), 0},
        {"port", 'p', N_("NUMBER"), 0,
         N_("show logins from given port"), 0},
        {"show-seconds", 's', NULL, 0,
         N_("show the login session duration in seconds"), 0},
        {"wide", 'w', NULL, 0,
         N_("widen the duration field to show seconds"), 0},
        {NULL, 0, NULL, 0, NULL, 0}
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
                if (maxrec == -1) {
                        char *p;
			int i;
			
			if (state->argv[state->next-1][1] == key)
				i = state->next-1;
			else
				i = state->next;
                        maxrec = strtoul(state->argv[i]+1, &p, 0);
                        if (!maxrec) {
                                grad_log(GRAD_LOG_ERR,
                                         "invalid number (near %s)",
                                         p);
                                exit(1);
                        }
                }
                break;
        case 'c':
                maxrec = atol(arg);
                if (!maxrec) {
                        grad_log(GRAD_LOG_ERR, "invalid number of records");
                        exit(1);
                }
                break;
        case 'f':
                file = arg;
                break;
        case 'h':
                host_ip = htonl(grad_ip_gethostaddr(arg));
                break;
        case 'm':
                mark_missing_stops++;
                break;
        case 'n':
                nas_name = arg;
                break;
        case 'l':
                long_fmt++;
                break;
        case 'p':
                if (*arg == 's' || *arg == 'S')
                        ++arg;
                port = atoi(arg);
                break;
        case 's':
                show_seconds++;        /* Show delta as seconds */
                break;
        case 't':
                if (*arg == 's' || *arg == 'S')
                        ++arg;
                port = atoi(arg);
                break;
        case 'w':
                width = 8;
                break;

        case ARGP_KEY_FINI:
                if (show_seconds && width == 8) {
                        grad_log(GRAD_LOG_ERR,
                                 _("--width is incompatible with --show-seconds"));
                        exit (1);
                }
                break;
                
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static struct argp argp = {
        options,
        parse_opt,
        NULL,
        doc,
        grad_common_argp_child,
        NULL, NULL
};

int
main(int argc, char **argv)
{
        int index;

        grad_app_setup();
        if (grad_argp_parse(&argp, &argc, &argv, 0, &index, NULL))
                return 1;

        argv += index;
        argc -= index;

        if (argc) {
                setlinebuf(stdout);
                for (; *argv; ++argv) 
                        adduser(*argv);
        }

        grad_dict_init();
        read_naslist();

        if (nas_name) {
		grad_nas_t *nas = grad_nas_lookup_name(nas_name);
		if (!nas) {
			if (grad_ip_getnetaddr(nas_name, &nas_ip)) {
                                grad_log(GRAD_LOG_ERR, "unknown nas: %s", nas_name);
                                return 1;
                        }
                }       
        }
        radwtmp();
        return 0;
}

int
read_naslist()
{
        int rc;
        char *path = grad_mkfilename(grad_config_dir, RADIUS_NASLIST);
        rc = grad_nas_read_file(path);
        grad_free(path);
        return rc;
}

#if 0
int
rawread()
{
        int wfd;
        struct radutmp ut;
        struct tm *tm;
        char ct[256];
        grad_uint32_t ipaddr;
        char ip_str[GRAD_IPV4_STRING_LENGTH];
        
        if ((wfd = open(file, O_RDONLY, 0)) < 0) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open file %s"), file);
                exit(1);
        }
        while (read(wfd, &ut, sizeof ut) == sizeof ut) {
                tm = localtime(&ut.time);
                strftime(ct, sizeof(ct), "%c", tm);

                ipaddr = ut.framed_address;
                grad_ip_iptostr(ntohl(ipaddr), ip_str);
                
                printf("%d %-*.*s %-*.*s %3.3d %-4.4s %2s %-*.*s %-*.*s %-*.*s %10.10s %5.5s\n",
                       ut.type,
                       
                       namesize, namesize,
                       ut.login,
                       
                       nas_name_len, nas_name_len,
                       grad_nas_ip_to_name(ntohl(ut.nas_address)),

                       ut.nas_port,

                       proto_str(ut.proto),

                       port_type_str(ut.porttype),

                       RUT_IDSIZE, RUT_IDSIZE,
                       ut.session_id,

                       RUT_PNSIZE, RUT_PNSIZE,
                       ut.caller_id[0] == 0 ? "?" : ut.caller_id,
                       
                       IP_ADDR_LEN, IP_ADDR_LEN,
                       ip_str,
                       
                       ct, ct + 11);
        }
        close(wfd);
        return;
}
#endif

volatile int stop;

RETSIGTYPE
sig_int(int sig)
{
        stop = 1;
}

void
radwtmp()
{
        int wfd;
        struct stat stb;
        int bl;
        struct radutmp *bp;
        int bytes;
        struct tm *tm;
        char ct[256];
        WTMP *pp;
	int acct_enabled = 0;
		
        if ((wfd = open(file, O_RDONLY, 0)) < 0 || fstat(wfd, &stb) == -1) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open file %s"), file);
                exit(1);
        }
        bl = (stb.st_size + sizeof(buf) - 1) / sizeof(buf);
        
        grad_set_signal(SIGINT, sig_int);
        stop = 0;

        /*time(&buf[0].ut_time);*/
        
        while (!stop && --bl >= 0) {
                if (lseek(wfd, (off_t)(bl * sizeof(buf)), SEEK_SET) == -1 ||
                    (bytes = read(wfd, buf, sizeof(buf))) == -1)
                        grad_log(GRAD_LOG_ERR, "%s", file);
                for (bp = &buf[bytes / sizeof(buf[0]) - 1]; !stop && bp >= buf;
		     --bp) {
                        switch (bp->type) {
                        case P_LOGIN:
                                if (pp = find_logout(bp)) {
                                        if (want(bp)) {
                                                print_entry(pp, bp, 0);
                                                if (maxrec != -1 && !--maxrec)
                                                        return;
                                        }
                                        delete_logout(pp, bp);
                                } else if (pp = find_restart(bp)) {
                                        if (want(bp)) {
                                                print_entry(pp, bp, 0);
                                                if (maxrec != -1 && !--maxrec)
                                                        return;
                                        }
                                } else if (pp = find_login(bp)) {
                                        /* Ignore duplicate logins */
                                        if (strncmp(pp->ut.session_id,
                                                   bp->session_id,
                                                   RUT_IDSIZE) == 0)
                                                break; 
                                        /*
                                         * This login misses logout
                                         */
                                        if (want(bp)) {
                                                print_entry(pp, bp,
                                                            mark_missing_stops);
                                                if (maxrec != -1 && !--maxrec)
                                                        return;
                                        }
                                        /* Update login information */
                                        pp->ut = *bp;
                                } else {
                                        if (want(bp)) {
                                                print_entry(NULL, bp, 0);
                                                if (maxrec != -1 && !--maxrec)
                                                        return;
                                        }
                                }
                                break;
                        case P_IDLE:
                                /*if (!find_logout_sid(bp))*/
                                        add_logout(bp);
                                break;
                        case P_NAS_SHUTDOWN:
                        case P_NAS_START:
                                add_nas_restart(bp);
                                if (want(bp)) {
                                        print_reboot_entry(bp);
                                        if (maxrec != -1 && !--maxrec)
                                                return;
                                }
                                break;
			case P_ACCT_DISABLED:
				if (!acct_enabled) {
					printf(_("System accounting is disabled\n"));
					stop = 1;
				} else
					print_acct_toggle(bp);
				break;
			case P_ACCT_ENABLED:
				acct_enabled = 1;
				print_acct_toggle(bp);
				break;
                        default:
                                break;
                        }
                }
        }
        
        tm = localtime(&buf[0].time);
        strftime(ct, sizeof(ct), "%c", tm);
        printf(_("\nradwtmp begins %s\n"), ct);
}

int
want(struct radutmp *ut)
{
        /* First see if it's a reboot/shutdown record and handle it
         * accordingly
         */  
        if (ut->type == P_NAS_START) {
                if (show_reboot_rec) 
                        return grad_ip_in_net_p(&nas_ip,
						ntohl(ut->nas_address));
        } else if (ut->type == P_NAS_SHUTDOWN) {
                if (show_shutdown_rec)
			return grad_ip_in_net_p(&nas_ip,
						ntohl(ut->nas_address));
        } else {
                /* Process ususal login/logout entry */
        
                if (user_chain) {
                        struct user_chain *cp;
                        
                        for (cp = user_chain; cp; cp = cp->next) {
                                if (strcmp(cp->name, ut->login) == 0) {
                                        if (host_ip != 0)
                                                return ut->framed_address == host_ip ;
                                        if (nas_ip.ipaddr != 0)
                                                return grad_ip_in_net_p(
						       &nas_ip,
						       ntohl(ut->nas_address));

                                        if (port != 0)
                                                return ut->nas_port == port;
                                        return 1;
                                }
                        }
                }
                if (show_reboot_rec || show_shutdown_rec)
                        return 0;

                if (host_ip != 0 && ut->framed_address == host_ip) 
                        return 1;

                if (nas_ip.ipaddr != 0 &&
		    grad_ip_in_net_p(&nas_ip,  ntohl(ut->nas_address)))
                        return 1;
        
                if (port != 0 && ut->nas_port == port)
                        return 1;
        }
        return host_ip == 0
		&& nas_ip.ipaddr == 0
		&& user_chain == 0
		&& port == 0;
}

void
adduser(char *s)
{
        struct user_chain *uc;

        if (*s == '~') {
                if (strcmp(s+1, "reboot") == 0)
                        show_reboot_rec = 1;
                else if (strcmp(s+1, "shutdown") == 0)
                        show_shutdown_rec = 1;
        }

        uc = grad_emalloc(sizeof(*uc));
        uc->next = NULL;
        if (user_last) 
                user_last->next = uc;
        else
                user_chain = uc;
        uc->name = grad_estrdup(s);
        user_last = uc;
}

/*
 * Add WTMP entry to the head of the list
 */
WTMP *
add_wtmp_entry(WTMP **first, WTMP *pp)
{
        assert(*first!=pp);
        pp->prev = NULL;
        pp->next = *first;
        if (*first)
                (*first)->prev = pp;
        *first = pp;
        return pp;
}

/*
 * Delete WTMP entry from the list.
 * NOTE: Does not free the entry itself
 */
WTMP *
delete_wtmp_entry(WTMP **first, WTMP *pp)
{
        WTMP *p;

        if (pp == *first) 
                *first = (*first)->next;
        if (p = pp->prev) 
                p->next = pp->next;
        if (p = pp->next)
                p->prev = pp->prev;
        return pp;
}

WTMP *
find_wtmp_nas(WTMP *first, struct radutmp *bp)
{
        WTMP *wp;
        
        for (wp = first; wp; wp = wp->next) {
                if (wp->ut.nas_address == bp->nas_address)
                        break;
        }
        return wp;
}

WTMP *
find_wtmp_nas_port(WTMP *first, struct radutmp *bp)
{
        WTMP *wp;
        
        for (wp = first; wp; wp = wp->next) {
                if (wp->ut.nas_address == bp->nas_address &&
                    wp->ut.nas_port == bp->nas_port) 
                        break;
        }
        return wp;
}

WTMP *
find_wtmp_nas_port_sid(WTMP *first, struct radutmp *bp)
{
        WTMP *wp;
        
        for (wp = first; wp; wp = wp->next) {
                if (wp->ut.nas_address == bp->nas_address &&
                    wp->ut.nas_port == bp->nas_port &&
                    strncmp(wp->ut.session_id, bp->session_id, RUT_IDSIZE)==0) 
                        break;
        }
        return wp;
}

/* ************************************************************************* */

void
add_logout(struct radutmp *bp)
{
        WTMP *wp;

        wp = grad_emalloc(sizeof(*wp));
        wp->ut = *bp;
        add_wtmp_entry(&logout_list, wp);
        /* purge deleted queue */
        if (wp = find_wtmp_nas_port(login_list, bp)) {
                delete_wtmp_entry(&login_list, wp);
                grad_free(wp);
        }
}

void
add_nas_restart(struct radutmp *bp)
{
        WTMP *wp;

        if (wp = find_wtmp_nas(nas_updown_list, bp)) {
                delete_wtmp_entry(&nas_updown_list, wp);
                grad_free(wp);
        }
                    
        wp = grad_emalloc(sizeof(*wp));
        wp->ut = *bp;
        add_wtmp_entry(&nas_updown_list, wp);
}

WTMP *
find_login(struct radutmp *bp)
{
        return find_wtmp_nas_port(login_list, bp);
}

WTMP *
find_logout_sid(struct radutmp *bp)
{
        return find_wtmp_nas_port_sid(logout_list, bp);
}

WTMP *
find_logout(struct radutmp *bp)
{
        return find_wtmp_nas_port(logout_list, bp) ;
}

WTMP *
find_restart(struct radutmp *bp)
{
        return find_wtmp_nas(nas_updown_list, bp);
}

void
delete_logout(WTMP *pp, struct radutmp *utp)
{
        static int count;
        
        delete_wtmp_entry(&logout_list, pp);
        pp->ut = *utp;
        count++;
        add_wtmp_entry(&login_list, pp);
}

/* ************************************************************************* */

char *
proto_str(int id)
{
        grad_dict_value_t *dval = grad_value_lookup(id, "Framed-Protocol");
        static char buf[64];
        
        if (!dval) {
                snprintf(buf, sizeof(buf), "%u", id);
                return buf;
        }
        return dval->name;
}

char *
port_type_str(int porttype)
{
	grad_dict_value_t *dval = grad_value_lookup(porttype, "NAS-Port-Type");
	static char buf[80];
	char *s;
	
        if (dval) 
		s = dval->name;
	else {
                snprintf(buf, sizeof buf, "%u", porttype);
		s = buf;
	}
	return s;
}

/* NOTE:
 *  short format is:
 * LOGIN      NAS     PORT FRAMED-IP       START_TIME - STOP_TIME (DURATION)
 *  long format is:
 * LOGIN      NAS     PORT PROTO PORT_TYPE SESSION_ID  CALLER_ID FRAMED-IP       START_TIME - STOP_TIME (DURATION)
 */
void
print_entry(WTMP *pp, struct radutmp *bp, int mark)
{
        struct tm *tm;
        char ct[256];
        char ip_str[IP_ADDR_LEN+1];
        time_t delta;
        grad_uint32_t ipaddr;
        char buf[GRAD_MAX_LONGNAME];
        
        tm = localtime(&bp->time);
        strftime(ct, sizeof(ct), "%a %b %d %H:%M", tm);

        ipaddr = bp->framed_address;
        if (ipaddr == 0 && pp)
                ipaddr = pp->ut.framed_address;
        grad_ip_iptostr(ntohl(ipaddr), ip_str);

        if (long_fmt) {                                   
                printf("%-*.*s %-*.*s %3.3d %-4.4s %2s %-*.*s %-*.*s %-*.*s %16.16s ",
                       namesize, namesize,
                       bp->login,
                       
                       nas_name_len, nas_name_len,
                       grad_nas_ip_to_name(ntohl(bp->nas_address),
					   buf, sizeof buf),

                       bp->nas_port,

                       proto_str(bp->proto),

                       port_type_str(bp->porttype),

                       RUT_IDSIZE, RUT_IDSIZE,
                       bp->session_id,

                       RUT_PNSIZE, RUT_PNSIZE,
                       bp->caller_id[0] == 0 ? "?" : bp->caller_id,
                       
                       IP_ADDR_LEN, IP_ADDR_LEN,
                       ip_str,
                       
                       ct);
        } else {
                printf("%-*.*s %-*.*s %3.3d %-*.*s %16.16s ",
                       namesize, namesize,
                       bp->login,
                       
                       nas_name_len, nas_name_len,
                       grad_nas_ip_to_name(ntohl(bp->nas_address),
					   buf, sizeof buf),

                       bp->nas_port,

                       IP_ADDR_LEN, IP_ADDR_LEN,
                       ip_str,
                       
                       ct);
        }
        
        if (pp == NULL) {
                printf(_("still logged in"));
        } else {
                tm = localtime(&pp->ut.time);
                strftime(ct, sizeof(ct), "%H:%M", tm);
                printf("- %5.5s", ct);

                /*delta = pp->ut.duration;*/
                delta = pp->ut.time - bp->time;
                if (show_seconds) {
                        printf("  (%8lu)", delta);
                } else {
                        if (delta < 0)
                                delta = 0;
                        tm = gmtime(&delta);
                        strftime(ct, sizeof(ct), "%H:%M:%S", tm);
                        if (delta < 86400)
                                printf("  (%*.*s)", width, width, ct);
                        else
                                printf(" (%ld+%*.*s)",
                                       delta / 86400, width, width, ct);
                }
        }
        if (mark)
                printf(" !");
        printf("\n");
}

void
print_reboot_entry(struct radutmp *bp)
{
        char *s;
        struct tm *tm;
        char ct[256];
        char buf[GRAD_MAX_LONGNAME];
        
        tm = localtime(&bp->time);
        strftime(ct, sizeof(ct), "%a %b %d %H:%M", tm);

        if (bp->type == P_NAS_SHUTDOWN)
                s = _("shutdown");
        else
                s = _("reboot");
        printf("%-*.*s %s      ~                   %16.16s\n",
               namesize, namesize,
               s,
                       
               grad_nas_ip_to_name(ntohl(bp->nas_address), buf, sizeof buf),
               ct);
}

void
print_acct_toggle(struct radutmp *bp)
{
        char *s;
        struct tm *tm;
        char ct[256];
        char buf[GRAD_MAX_LONGNAME];
        
        tm = localtime(&bp->time);
        strftime(ct, sizeof(ct), "%a %b %d %H:%M", tm);

        if (bp->type == P_ACCT_DISABLED)
                s = _("acct_off");
        else
                s = _("acct_on");
        printf("%-*.*s %s      ~                   %16.16s\n",
               namesize, namesize,
               s,
                       
               grad_nas_ip_to_name(ntohl(bp->nas_address), buf, sizeof buf),
               ct);
}





