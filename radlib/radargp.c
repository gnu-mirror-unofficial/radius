/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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
#include <radius.h>

const char *argp_program_bug_address = "<bug-gnu-radius@gnu.org>";

static struct argp_option rad_common_argp_option[] = {
	{"directory", 'd', "DIR", 0,
	 "Set path to the configuration directory", 0},
	{ "license", 'L', NULL, 0, "print license and exit", 0 },
	{ NULL,      0, NULL, 0, NULL, 0 }
};

static error_t rad_common_argp_parser (int key, char *arg,
				       struct argp_state *state);

struct argp rad_common_argp = {
	rad_common_argp_option,
	rad_common_argp_parser,
	"",
	"",
	NULL,
	NULL,
	NULL
};

struct argp_child rad_common_argp_child = {
	&rad_common_argp,
	0,
       	"Common options",
       	1
};


static char license_text[] =
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

static error_t 
rad_common_argp_parser (key, arg, state)
	int key;
	char *arg;
	struct argp_state *state;
{
	char *p;
	
	switch (key) {
	case 'd':
		radius_dir = arg;
		break;

	case 'L':
		printf ("%s", license_text);
		exit (0);

	case ARGP_KEY_FINI:
		radpath_init();
		break;
      
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

char *progname;

error_t
rad_argp_parse(argp, pargc, pargv, flags, arg_index, input)
	const struct argp *argp;
	int *pargc;
	char **pargv[];
	unsigned flags;
	int *arg_index;
	void *input;
{
	error_t ret;
  
        if ((progname = strrchr((*pargv)[0], '/')) == NULL)
                progname = (*pargv)[0];
        else
                progname++;

	ret = argp_parse (argp, *pargc, *pargv, flags, arg_index, input);
	return ret;
}
