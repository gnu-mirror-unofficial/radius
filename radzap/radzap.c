/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
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

#include <getopt1.h>
#include <radius.h>
#include <radpaths.h>
#include <radutmp.h>

#define LOCK_LEN sizeof(struct radutmp)

static int write_wtmp(struct radutmp *ut);
int radzap(UINT4 nasaddr, int port, char *user, time_t t);
static int confirm(struct radutmp *ut);
UINT4 findnas(char *nasname);

int confirm_flag;
void usage();
void license();

#define OPTSTR "cd:hl:Ln:p:qw"

struct option longopt[] = {       
        "confirm",             no_argument, 0, 'c',
        "directory",     required_argument, 0, 'd',
        "help",                no_argument, 0, 'h',
        "license",             no_argument, 0, 'L',
        "log-directory", required_argument, 0, 'l',
        "nas",           required_argument, 0, 'n',
        "port",          required_argument, 0, 'p',
        "quiet",               no_argument, 0, 'q',
        0
};

/*
 *      Zap a user from the radutmp and radwtmp file.
 */
int
main(argc, argv)
        int argc;
        char **argv;
{
        int c;
        int     nas_port = -1;
        char    *user = NULL;
        char    *nas = NULL;
        UINT4   ip = 0;
        time_t  t;
        char    *path;
        char *s;        

        app_setup();
        initlog(argv[0]);

        if (s = getenv("RADZAP_CONFIRM"))
                confirm_flag = atoi(s);
        while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF) {
                switch (c) {
                case 'c':
                        confirm_flag = 1;
                        break;
                case 'd':
                        radius_dir = optarg;
                        break;
                case 'l':
                        radlog_dir = optarg;
                        break;
                case 'n':
                        nas = optarg;
                        break;
                case 'p':
                        if (*optarg == 's' || *optarg == 'S')
                                ++optarg;
                        nas_port = atoi(optarg);
                        break;
                case 'q':
                        confirm_flag = 0;
                        break;
                case 'h':
                        usage();
                        return 0;
                case 'L':
                        license();
                        return 0;
                default :
                        usage();
                        return 0;
                }
        }

        radpath_init();
        
        if (argc > optind)
                user = argv[optind];
        /* check the validity of the invocation */
        if (!user && !nas && nas_port == -1) {
                usage();
                return 1;
        }

        /*
         *      Read the "naslist" file.
         */
        path = mkfilename(radius_dir, RADIUS_NASLIST);
        if (nas_read_file(path) < 0)
                exit(1);
        efree(path);

        if (nas) {
                NAS *np;
                np = nas_lookup_name(nas);
                if (np)
                        ip = np->ipaddr;
                else if ((ip = ip_gethostaddr(nas)) == 0) {
                        fprintf(stderr, "%s: host not found.\n", nas);
                        return 1;
                }
        }
                
        t = time(NULL);
        radzap(ip, nas_port, user, t);
        return 0;
}

/*
 *      Zap a user, or all users on a NAS, from the radutmp file.
 */
int
radzap(nasaddr, port, user, t)
        UINT4 nasaddr;
        int port;
        char *user;
        time_t t;
{
        struct radutmp  *up;
        radut_file_t    file;
        UINT4           netaddr;

        if (t == 0) 
                time(&t);

        netaddr = htonl(nasaddr);

        if ((file = rut_setent(radutmp_path, 0)) == NULL) {
                radlog(L_ERR|L_PERROR, "can't open %s", radutmp_path);
                exit(1);
        }       
        /*
         *      Find the entry for this NAS / portno combination.
         */
        while (up = rut_getent(file)) {
                if ((nasaddr != 0 && netaddr != up->nas_address) ||
                      (port >= 0   && port    != up->nas_port) ||
                      (user != NULL && strcmp(up->login, user))!= 0 ||
                       up->type != P_LOGIN) {
                        continue;
                }
                if (!confirm(up))
                        continue;

                up->type = P_IDLE;
                up->time = t;
                rut_putent(file, up);
                write_wtmp(up);
        }
        rut_endent(file);

        return 0;
}

int
confirm(utp)
        struct radutmp *utp;
{
        char buf[MAX_LONGNAME];
        NAS *cl;
        char *s;
        
        if (cl = nas_lookup_ip(ntohl(utp->nas_address)))
                s = cl->shortname;
        if (s == NULL || s[0] == 0) 
                s = ip_gethostname(ntohl(utp->nas_address), buf, sizeof(buf));
        
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
write_wtmp(ut)
        struct radutmp *ut;
{
        return radwtmp_putent(radwtmp_path, ut);
}

char usage_text[] =
"usage: radzap [-c][-q][-d raddb][-L][-l log_dir] [-n nas][-p port] [user]\n"
"either nas or port or user must be specified\n"
"\n"
"Options are:\n"
"       -c, --confirm            Ask for confirmation before zapping.\n"
"       -d, --directory DIR      Specify Radius configuration directory.\n"
"       -L, --license            Display GNU license and exit.\n"
"       -l, --log-directory DIR  Specify logging directory.\n"
"       -n, --nas NASNAME        NAS from which to zap the user.\n"
"       -p, --port PORT          Port to zap from.\n"
"       -q, --quiet              Do not ask for confirmation before zapping.\n";

void
usage()
{
        printf("%s", usage_text);
        printf("\nReport bugs to <%s>\n", bug_report_address);
}

char license_text[] =
"   This program is free software; you can redistribute it and/or modify\n"
"   it under the terms of the GNU General Public License as published by\n"
"   the Free Software Foundation; either version 2, or (at your option)\n"
"   any later version.\n"
"\n"
"   This program is distributed in the hope that it will be useful,\n"
"   but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"   GNU General Public License for more details.\n"
"\n"
"   You should have received a copy of the GNU General Public License\n"
"   along with this program; if not, write to the Free Software\n"
"   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n";

void
license()
{
        printf("%s: Copyright 1999,2000 Sergey Poznyakoff\n", progname);
        printf("\nThis program is part of GNU Radius\n");
        printf("%s", license_text);
}
