/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2005,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <argp.h>
#include <common.h>

const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";

static struct argp_option rad_common_argp_option[] = {
        {"directory", 'd', N_("DIR"), 0,
         N_("Set path to the configuration directory"), 0},
        { "license", 'L', NULL, 0, N_("print license and exit"), 0 },
        { NULL,      0, NULL, 0, NULL, 0 }
};

static error_t rad_common_argp_parser (int key, char *arg,
                                       struct argp_state *state);

struct argp grad_common_argp = {
        rad_common_argp_option,
        rad_common_argp_parser,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};

struct argp_child grad_common_argp_child[] = {
        { &grad_common_argp, 0, N_("Common options"), 1 },
	{ NULL },
};

char *
__argp_base_name(const char *arg)
{
	const char *p = strrchr(arg, '/');
	if (!p)
		p = arg;
	else
		p++;
	return (char*)p;
}

static char license_text[] = N_(
    "   This program is free software; you can redistribute it and/or modify\n"
    "   it under the terms of the GNU General Public License as published by\n"
    "   the Free Software Foundation; either version 3, or (at your option)\n"
    "   any later version.\n"
    "\n"
    "   This program is distributed in the hope that it will be useful,\n"
    "   but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
    "   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
    "   GNU General Public License for more details.\n"
    "\n"
    "   You should have received a copy of the GNU General Public License\n"
    "   along with GNU Radius; if not, write to the Free Software Foundation,\n"
    "   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n"
    "\n"
);


static error_t 
rad_common_argp_parser(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'd':
                grad_config_dir = arg;
                break;

        case 'L':
                printf ("%s", _(license_text));
                exit (0);

        case ARGP_KEY_FINI:
                grad_path_init();
                break;
      
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

error_t
grad_argp_parse(const struct argp *argp, int *pargc, char **pargv[],
		unsigned flags, int *arg_index, void *input)
{
        error_t ret;
#ifndef PROGRAM_INVOCATION_NAME_DECLARED
        program_invocation_name = (*pargv[0]);
        program_invocation_short_name = strrchr(program_invocation_name, '/');
        if (!program_invocation_short_name)
                program_invocation_short_name = program_invocation_name;
	else
		program_invocation_short_name++;
#endif
        ret = argp_parse (argp, *pargc, *pargv, flags, arg_index, input);
        return ret;
}

