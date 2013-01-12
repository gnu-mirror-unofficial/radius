/* This file is part of GNU RADIUS.
   Copyright (C) 1999,2000,2001,2007,2008,2013 Free Software Foundation, Inc.
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. */
      
#include <raduse.h>
#include <radius/radargp.h>

int width = 5;            /* width for time output (5 - hh:mm, 8 - hh:mm:ss) */
int delay = 1;            /* delay between screen updates (seconds) */
int maxscreens = -1;      /* max. number of screens to display */
int numscreens = 0;       /* number of screens displayed so far */
int brief = 0;            /* brief mode (don't show inuse/idle statistics) */
int show_idle = 1;        /* show idle lines */
int interactive = -1;     /* interactive mode */
int dump_only = 0;

char *hostname;
char *community;
int port = 0;

const char *argp_program_version = "raduse (" PACKAGE ") " VERSION;
static char doc[] = "Monitor the usage of dialup lines";

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         "raduse specific switches:", 0},
        {"host", 'H', "HOSTNAME", 0,
         "", 0},
        {"port", 'p', "NUMBER", 0,
         "", 0},
        {"community", 'C', "STRING", 0,
         "", 0},
        {"format", 'f', "STRING", 0,
         "", 0},
        {NULL, 0, NULL, 0, NULL, 0}
};

static error_t
parse_opt (key, arg, state)
        int key;
        char *arg;
        struct argp_state *state;
{
        switch (key) {
        case 'H':
                hostname = optarg;
                break;
        case 'p':
                port = atoi(optarg);
                break;
        case 'C':
                community = optarg;
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
main(argc, argv)
        int argc;
        char **argv;
{
        app_setup();    

        if (grad_argp_parse(&argp, &argc, &argv, 0, NULL, NULL))
                return 1;
        
        grad_path_init();
        snmp_init(0, 0, grad_emalloc, grad_free);
        test();
}

int
unimplemented(c)
        int c;
{
        grad_log(GRAD_LOG_ERR, "option %c is not implemented", c);
        exit(1);
}


