/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
  
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <netinet/in.h>

#include <sysdep.h>
#include <radutmp.h>
#include <radius.h>
#include <radargp.h>
#include <radpaths.h>

void local_who();
void radius_who();

#define P_CONSOLE -1  /* Special radutmp type value for local users */

int  fingerd;             /* Are we run as fingerd */
int  secure;              /* Secure mode: do not answer queries w/o username */
int  showlocal;           /* Display local users as well */
int  display_header = 1;  /* Display header line */
int  showall;             /* Display all records */

char *username = NULL;

char *filename = NULL;    /* radutmp filename */
char *eol = "\n";         /* line delimiter */

static struct {
	char *name;
	char *fmt;
} fmtdef[] = {
	{ "default",
	  "(login 10 Login) (gecos 17 Name) (protocol 5 Proto) (nas-port 5 TTY) (time 9 When) (nas-address 9 From) (framed-address 16 Location)" },
	{ "sid",
	  "(login 10 Login) (session-id 17 SID) (protocol 5 Proto) (nas-port 5 TTY) (time 9 When) (nas-address 9 From) (framed-address 16 Location)" },
	{ "clid",
	  "(login 10 Login) (clid 17 CLID) (protocol 5 Proto) (nas-port 5 TTY) (time 9 When) (nas-address 9 From) (framed-address 16 Location)" },
	{ "long",
	  "(login 32 Login) (session-id 32 SID) (protocol 5 Proto) (nas-port 5 Port) (time 27 Date) (nas-address 32 NAS) (clid 17 CLID) (duration 7 Duration) (framed-address 16 Location) (realm 16 Realm)" },
	{ "gnu",
	  "User: (login)(newline)\
In real life: (gecos)(newline)\
Logged in: (time)(newline)\
NAS: (nas-address)(newline)\
Port: (nas-port)(newline)\
CLID: (clid)(newline)\
Protocol: (protocol)(newline)\
Session ID: (session-id)(newline)\
Uptime: (duration)(newline)\
Assigned IP: (framed-address)(newline)\
Realm: (realm)(newline)" },

	NULL
};

static char *
lookup_format(name)
	char *name;
{
	int i;
	for (i = 0; fmtdef[i].name; i++)
		if (strcmp(fmtdef[i].name, name) == 0)
			return fmtdef[i].fmt;
	return name;
}

char *fmtspec = NULL;
format_data_t *form;

const char *argp_program_version = "radwho (" PACKAGE ") " VERSION;
static char doc[] = N_("display who is logged on by Radius");

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         N_("radwho specific switches:"), 0},
        {"all", 'A', NULL, 0,
         N_("print all entries, not only active ones"), 0},
        {"calling-id", 'c', NULL, 0,
         N_("display CLID in second column"), 0},
        {"date-format", 'D', "DATEFMT", 0,
         N_("change date representation format"), 0},
        {"empty", 'e', "STRING", 0,
         N_("print STRING instead of an empty column"), 0},
        {"file", 'f', "FILE", 0,
         N_("Use FILE instead of /var/log/radutmp"), 0},
        {"finger", 'F', NULL, 0,
         N_("act as a finger daemon"), 0},
        {"no-header", 'H', NULL, 0,
         N_("do not display header line"), 0},
        {"session-id", 'i', NULL, 0,
         N_("display session ID in the second column"), 0},
        {"ip-strip-domain", 'I', NULL, 0,
         N_("display hostnames without domain part"), 0},
        {"long", 'l', NULL, 0,
         N_("Long output. All fields will be printed."),
         0},
        {"local-also", 'u', NULL, 0,
         N_("display also local users"), 0},
        {"no-resolve", 'n', NULL, 0,
         N_("do not resolve hostnames."), 0},
        {"format", 'o', "FORMAT", 0,
         N_("change output format"), 0},
        {"secure", 's', NULL, 0,
         N_("secure mode: requires that the username be specified"), 0},
        {NULL, 0, NULL, 0, NULL, 0}
};

static error_t
parse_opt (key, arg, state)
        int key;
        char *arg;
        struct argp_state *state;
{
        switch (key) {
        case 'A': /* display all entries */
                showall++;
                break;
        case 'c': /* CLID instead of GECOS */
                fmtspec = lookup_format("clid");
                break;
        case 'D': /* Date format */
                printutmp_date_format = optarg;
                break;
        case 'e': /* empty field replacement */
                printutmp_empty_string = optarg;
                break;
        case 'f': /* filename */
                filename = optarg;
                break;
        case 'F':
                fingerd++;
                break;
        case 'H': /* Disable header line */
                display_header = 0;
                break;
        case 'i': /* Display SID instead of GECOS */
                fmtspec = lookup_format("sid");
                break;
        case 'I': /* Ipaddr format */
                /*FIXME set_ip_format(optarg);*/
                break;
        case 'l': /* long output */
                fmtspec = lookup_format("long");
                break;
        case 'n':
                resolve_hostnames = 0;
                break;
        case 'o':
                fmtspec = lookup_format(optarg);
                break;
        case 's':
                secure++;
                break;
        case 'u':
                showlocal++;
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
        &rad_common_argp_child,
        NULL, NULL
};


int
main(argc, argv)
        int  argc;
        char **argv;
{
        char inbuf[128];
        char *path;
        char *p, *q;
        int index;

        app_setup();
        initlog(argv[0]);
        if (rad_argp_parse(&argp, &argc, &argv, 0, &index, NULL))
                return 1;

        if (!fmtspec)
                fmtspec = getenv("RADWHO_FORMAT");

        if (!fmtspec)
                fmtspec = lookup_format("default");

	form = radutent_compile_form(fmtspec);
	if (!form)
		exit(1);

        if (!filename)
                filename = radutmp_path;
        
        /* Read the dictionary files */
        dict_init();
        /* Read the "naslist" file. */
        path = mkfilename(radius_dir, RADIUS_NASLIST);
	if (nas_read_file(path))
                exit(1);
        efree(path);
        /* Read realms */
        path = mkfilename(radius_dir, RADIUS_REALMS);
	realm_read_file(path, 0, 0);
        efree(path);
        
        /*
         *      See if we are "fingerd".
         */
        if (strstr(argv[0], "fingerd")) 
                fingerd++;

        if (fingerd) {
                eol = "\r\n";
                /*
                 *      Read first line of the input.
                 */
                fgets(inbuf, sizeof(inbuf), stdin);
                p = inbuf;
                while(*p == ' ' || *p == '\t') p++;
                if (*p == '/' && *(p + 1)) p += 2;
                while(*p == ' ' || *p == '\t') p++;
                for(q = p; *q && *q != '\r' && *q != '\n'; q++)
                        ;
                *q = 0;
                if (*p)
                        username = p;

                /*
                 *      See if we fingered a specific user.
                 */
                if (secure && username == 0) {
                        printf(_("must provide username\n"));
                        exit(1);
                }
        }

        if (showlocal)
                local_who();

        radius_who();

        fflush(stdout);
        fflush(stderr);

        return 0;
}

void
tty_to_port(rt, tty)
        struct radutmp *rt;
        char *tty;
{
        char *p;

        p = tty + strlen(tty) - 1; 
        while (p >= tty && isdigit(*p))
                p--;
        rt->nas_port = atoi(p+1);
        rt->porttype = 0;/*FIXME*/
}

void
local_who()
{
        FILE  *fp;
        struct utmp ut;
        struct radutmp rt;
        
        if ((fp = fopen(UTMP_FILE, "r")) == NULL) {
                radlog(L_ERR, _("can't open file: %s"),
                       UTMP_FILE);
                return;
        }

        print_header();

        memset(&rt, 0, sizeof(rt));
        rt.nas_address = rt.framed_address = htonl(INADDR_LOOPBACK);
        
        while(fread(&ut, sizeof(ut), 1, fp) == 1) {
#ifdef USER_PROCESS
                if (ut.ut_user[0] && ut.ut_line[0] &&
                    ut.ut_type == USER_PROCESS) {
#else
                if (ut.ut_user[0] && ut.ut_line[0]) {
#endif
                        rt.type = P_CONSOLE;
                        strncpy(rt.login, ut.ut_name, RUT_NAMESIZE);
                        strncpy(rt.orig_login, ut.ut_host, RUT_NAMESIZE);
#if defined __svr4__ || defined __sgi
                        rt.time = ut.ut_xtime;
#else
                        rt.time = ut.ut_time;
#endif
                        tty_to_port(&rt, ut.ut_line);
                        if (want_rad_record(&rt)) 
                                radutent_print(form, &rt, 1);
                }
        }
        fclose(fp);
}

void
radius_who()
{
        radut_file_t file;
        struct radutmp *up;
        print_header();

        /*
         *      Show the users logged in on the terminal server(s).
         */
        if ((file = rut_setent(filename, 0)) == NULL)
                return ;

        while (up = rut_getent(file)) {
                if (want_rad_record(up)) 
                        radutent_print(form, up, 1);
        }
        rut_endent(file);
}

void
print_header()
{
        if (display_header) {
                printutmp_header(form);
                display_header = 0;
        }
}

int
want_rad_record(rt)
        struct radutmp *rt;
{
        if (username && strcmp(rt->login, username))
                return 0;
        
        switch (showall) {
        case 0:
                return rt->type != P_IDLE;
        case 1:
                return rt->login[0] != 0;
        case 2:
        default:
                return (rt->type == P_IDLE && rt->login[0] != 0);
        }
}


