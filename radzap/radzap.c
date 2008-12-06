/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>

#include <common.h>
#include <radius/radargp.h>
#include <radius/radutmp.h>

#define LOCK_LEN sizeof(struct radutmp)

int confirm_flag;

struct arguments {
	char *radutmp;
        char *user;
        char *nas;
        int port;
};
const char *argp_program_version = "radzap (" PACKAGE ") " VERSION;
static char doc[] = N_("delete Radius login records");

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         N_("radzap specific switches:"), 0},
        {"confirm", 'c', NULL, 0,
         N_("ask for confirmation before zapping"), 0},
        {"log-directory", 'l', "DIR", 0,
         N_("set logging directory"), 0},
        {"file", 'f', N_("FILE"), 0,
         N_("operate on FILE instead of /var/log/radutmp"), 0},
        {"nas", 'n', N_("NASNAME"), 0,
         N_("zap user from given NAS"), 0},
        {"port", 'p', N_("NUMBER"), 0,
         N_("zap user coming from given port"), 0},
        {"quiet", 'q', NULL, 0,
         N_("do not ask for confirmation before zapping"), 0},
        {NULL, 0, NULL, 0, NULL, 0}
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
        struct arguments *args = state->input;
        
        switch (key) {
        case 'c':
                confirm_flag = 1;
                break;
        case 'l':
                grad_log_dir = arg;
                break;
        case 'f':
                args->radutmp = arg;
                break;
        case 'n':
                args->nas = arg;
                break;
        case 'p':
                if (*arg == 's' || *arg == 'S')
                        ++arg;
                args->port = atoi(arg);
                break;
        case 'q':
                confirm_flag = 0;
                break;
        case ARGP_KEY_ARG:
                args->user = state->argv[state->next - 1];
                break;
        case ARGP_KEY_FINI:
                if (!args->user && !args->nas && args->port == -1) {
                        grad_log(GRAD_LOG_ERR,
                                 _("at least one port, nas or user must be specified"));
                        exit(1);
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


/*
 *      Zap a user, or all users on a NAS, from the radutmp file.
 */
int
radzap(grad_netdef_t *netdef, int port, char *user, time_t t)
{
        struct radutmp  *up;
        radut_file_t    file;
        grad_uint32_t   netaddr;

        if (t == 0) 
                time(&t);

        if ((file = grad_ut_setent(grad_utmp_file, 0)) == NULL) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open file %s"), grad_utmp_file);
                exit(1);
        }       
        /*
         *      Find the entry for this NAS / portno combination.
         */
        while (up = grad_ut_getent(file)) {
                if ((netdef
		     && !grad_ip_in_net_p(netdef, htonl(up->nas_address)))
		    || (port >= 0 && port != up->nas_port)
		    || (user != NULL && strcmp(up->login, user))!= 0
		    ||  up->type != P_LOGIN) {
                        continue;
                }
                if (!confirm(up))
                        continue;

                up->type = P_IDLE;
                up->time = t;
                grad_ut_putent(file, up);
                write_wtmp(up);
        }
        grad_ut_endent(file);

        return 0;
}

int
confirm(struct radutmp *utp)
{
        char buf[GRAD_MAX_LONGNAME];
        grad_nas_t *cl;
        char *s = NULL;
        
        if (cl = grad_nas_lookup_ip(ntohl(utp->nas_address)))
                s = cl->shortname;
        if (s == NULL || s[0] == 0) 
                s = grad_ip_gethostname(ntohl(utp->nas_address),
					buf, sizeof(buf));
        
        printf(_("radzap: zapping %s from %s, port %d"),
               utp->login,
               s,
               utp->nas_port);
        if (confirm_flag) {
                printf(": Ok?");
                fgets(buf, sizeof(buf), stdin);
                if (buf[0] != 'y' && buf[0] != 'Y') {
                        printf(_("Not confirmed\n"));
                        return 0;
                } else
                        return 1;
        } 
        printf("\n");
        return 1;
}

int
write_wtmp(struct radutmp *ut)
{
        return grad_radwtmp_putent(grad_wtmp_file, ut);
}

/*
 *      Zap a user from the radutmp and radwtmp file.
 */
int
main(int argc, char **argv)
{
        grad_netdef_t netdef, *netdefp = NULL;
        time_t  t;
        char    *path;
        char *s;        
        struct arguments args;
        
        grad_app_setup();

        if (s = getenv("RADZAP_CONFIRM"))
                confirm_flag = atoi(s);
	args.radutmp = NULL;
        args.user = NULL;
        args.nas  = NULL;
        args.port = -1;
        if (grad_argp_parse(&argp, &argc, &argv, 0, NULL, &args))
                return 1;
	if (args.radutmp)
		grad_utmp_file = args.radutmp;

        /*
         *      Read the "naslist" file.
         */
        path = grad_mkfilename(grad_config_dir, RADIUS_NASLIST);
        if (grad_nas_read_file(path) < 0)
                exit(1);
        grad_free(path);

        if (args.nas) {
                grad_nas_t *np;
                np = grad_nas_lookup_name(args.nas);
		if (np) {
                        netdefp = &np->netdef;
		} else {
			if (grad_ip_getnetaddr(args.nas, &netdef)) {
				fprintf(stderr,
					_("%s: host not found.\n"), args.nas);
				return 1;
			}
			netdefp = &netdef;
                } 
        }
                
        t = time(NULL);
        radzap(netdefp, args.port, args.user, t);
        return 0;
}

