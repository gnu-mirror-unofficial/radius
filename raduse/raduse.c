/* This file is part of GNU RADIUS.
   Copyright (C) 1999,2000,2001, Sergey Poznyakoff
  
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
#include <getopt1.h>

int width = 5;            /* width for time output (5 - hh:mm, 8 - hh:mm:ss) */
int delay = 1;            /* delay between screen updates (seconds) */
int maxscreens = -1;      /* max. number of screens to display */
int numscreens = 0;       /* number of screens displayed so far */
int brief = 0;            /* brief mode (don't show inuse/idle statistics) */
int show_idle = 1;        /* show idle lines */
int interactive = -1;     /* interactive mode */
int dump_only = 0;

#define OPTSTR "bC:Dd:H:hIilLnps:wx"

struct option longopt[] = {
        "brief",         no_argument,       0, 'b',
        "display",       required_argument, 0, 'd',
        "dump",          no_argument,       0, 'D',
        "no-idle-lines", no_argument,       0, 'I',
        "interactive",   no_argument,       0, 'i',
        "no-interactive",no_argument,       0, 'n',
        "delay",         required_argument, 0, 's',
        "widen",         no_argument,       0, 'w',
        "license",       no_argument,       0, 'L',
        "list-nas",      no_argument,       0, 'l',
        "help",          no_argument,       0, 'h',
	
	"host",          required_argument, 0, 'H',
	"port",          required_argument, 0, 'p',
	"community",     required_argument, 0, 'C', 
        0,
};

char *hostname;
char *community;
int port = 0;

static void usage();
static void license();

int
main(argc, argv)
	int argc;
	char **argv;
{
        int c;
	
        app_setup();    
        initlog(argv[0]);
        while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF)
                switch(c) {
		case 'H':
			hostname = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'C':
			community = optarg;
			break;
			
                case 'b':
                        brief = !brief;
                        break;
                case 'd':
                        maxscreens = atoi(optarg);
                        break;
                case 'D':
                        dump_only++;
                        break;
                case 'h':
                        usage();
                        /*NOTREACHED*/
                case 'I':
                        show_idle = !show_idle;
                        break;
                case 'i':
                        interactive = 1;
                        break;
                case 'L':
                        license();
                        return 0;
                case 'l':
			unimplemented(c);
                        return 0;
                case 'n':
                        interactive = 0;
                        break;
                case 's':
                        delay = atoi(optarg);
                        break;
                case 'w':
                        width = 8;
                        break;
#ifdef DEBUG
                case 'x':
                        stop = 0;
                        break;
#endif                  
                default:
                        exit(1);
                }
	
	radpath_init();
	snmp_init(0, 0, emalloc, efree);
	test();
}

int
unimplemented(c)
	int c;
{
	radlog(L_ERR, "option %c is not implemented", c);
	exit(1);
}

char usage_str[] = 
"usage: raduse [options] [nas [nas...]]\n"
"The options are:\n"
"       -b, --brief               Brief mode.\n"
"       -d, --display COUNT       Show only COUNT displays.\n"
"       -D, --dump                Dump the statistics database to stdout\n"
"                                 and exit.\n"
"       -I, --no-idle-lines       Do not display idle lines.\n"
"       -i, --interactive         Interactive mode.\n"
"       -n, --no-interactive      Non-interactive mode.\n"
"       -s, --delay NUM           Specify delay in seconds between\n"
"                                 screen updates.\n"
"       -w, --widen               Widen the time display fields to show\n"
"                                 the seconds.\n"
"       -l, --list-nas            List the names and IP numbers of\n"
"                                 network access servers and then exit.\n"
"       -L, --license             Display GNU lisense and exit\n"
"       -h, --help                Display short usage summary.\n";

void 
usage()
{
        printf("%s", usage_str);
        printf("\nReport bugs to <%s>\n", bug_report_address);
        exit(1);
}

static char license_text[] = "\
\n\
  This program is free software; you can redistribute it and/or modify\n\
  it under the terms of the GNU General Public License as published by\n\
  the Free Software Foundation; either version 2 of the License, or\n\
  (at your option) any later version.\n\
\n\
  This program is distributed in the hope that it will be useful,\n\
  but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
  GNU General Public License for more details.\n\
 \n\
  You should have received a copy of the GNU General Public License\n\
  along with this program; if not, write to the Free Software\n\
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.\n\
";

void
license()
{
        printf("%s: Copyright 1999,2000,2001 Sergey Poznyakoff\n", progname);
        printf("\nThis program is part of GNU Radius\n");
        printf("%s", license_text);
        exit(0);
}

