/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef lint
static char rcsid[] = 
	"@(#) $Id$";
#endif
#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif
#include <radiusd.h>
#include <radclient.h>
#include <log.h>
#include <radtest.h>

#define OPTSTR "a:d:hLp:qr:s:t:vx:V"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {
	"assign", required_argument, 0, 'a',
	"debug", required_argument, 0, 'x',
	"directory", required_argument, 0, 'd',
	"help", no_argument, 0, 'h',
	"license", no_argument, 0, 'L',
	"port", required_argument, 0, 'p',
	"quick", no_argument, 0, 'q',
	"retry", required_argument, 0, 'r',
	"server", required_argument, 0, 's',
	"timeout", required_argument, 0, 't',
	"verbose", no_argument, 0, 'v', 
	"version", no_argument, 0, 'V',
	0
};
#else
# define longopt 0
# define getopt_long(ac,av,os,lo,li) getopt(ac,av,os)
#endif

#define RCFILE "radtestrc"

Symtab *vartab;
char *radius_dir = RADIUS_DIR;
int verbose;
extern RADCLIENT *radclient;
extern int radclient_debug;

void init_symbols();
static void print_usage();
static void print_license();
static void print_version();
static void assign(char *);

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	int quiet = 0;
	char *p;
	
	app_setup();
	initlog(argv[0]);
	init_symbols();
	
	while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF) {
		switch (c) {
		case 'a':
			assign(optarg);
			break;
		case 'd':
			radius_dir = optarg;
			break;
		case 'h':
			print_usage();
			break;
		case 'L':
			print_license();
			break;
		case 'p':
			break;
		case 'q':
			quiet++;
			break;
		case 'r':
			break;
		case 's':
			break;
		case 't':
			break;
		case 'x':
			set_debug_levels(optarg);
			break;
		case 'v':
			verbose++;
			radclient_debug++;
			break;
		case 'V':
			print_version();
			break;
		default:
			print_usage();
			return 1;
		}
	}

	set_yydebug();
	radpath_init();
	if (dict_init(NULL)) {
		radlog(L_ERR, _("error reading dictionary file"));
		return 1;
	}
	radclient = radclient_init(NULL);
	if (!radclient)
		return 1;
	
	if (!quiet) {
		struct stat sb;
		struct passwd *pw;
		char *buffer;
		int len, len1;

		pw = getpwuid(getuid());
		len = strlen(radius_dir) + sizeof(RCFILE) + 1;
		len1 = strlen(pw->pw_dir) + sizeof(RCFILE) + 2;
		if (len < len1)
			len = len1;
		buffer = emalloc(len);
		sprintf(buffer, "%s/%s", radius_dir, RCFILE);
		if (stat(buffer, &sb) == 0) {
			if (open_input(buffer) == 0) {
				yyparse();
				close_input();
			}
		}
		sprintf(buffer, "%s/.%s", pw->pw_dir, RCFILE);
		if (stat(buffer, &sb) == 0) {
			if (open_input(buffer) == 0) {
				yyparse();
				close_input();
			}
		}
	}
	
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		open_input(NULL);
		return yyparse();
	}
	
	for (; argc; argc--, argv++) {
		if ((p = strchr(*argv, '=')) != NULL &&
		    !(p > *argv && p[-1] == '\\')) {
			assign(*argv);
		} else {
			if (open_input(*argv))
				continue;
			yyparse();
			close_input(*argv);
		}
	}
	return 0;
}

void
init_symbols()
{
	Variable *var;
	
	vartab = symtab_create(sizeof(Variable), 0, NULL);
	var = (Variable*) sym_install(vartab, "REPLY_CODE");
	var->type = Integer;
	var = (Variable*) sym_install(vartab, "REPLY");
	var->type = Vector;
}

void
assign(s)
	char *s;
{
	char *p;
	Variable *var;
	union datum datum;
	int type = Undefined;
	int length;
	
	p = strchr(s, '=');
	if (!p) {
		fprintf(stderr, _("assign: expected `='\n"));
		return;
	}
	*p++ = 0;

	if (*p == '"') {
		length = strlen(++p);
		if (length == 0 || p[length-1] != '"') {
			fprintf(stderr, _("assign: missing closing quote\n"));
			return;
		}
		p[length-1] = 0;
		
		if (length > MAX_STRING) {
			fprintf(stderr, _("assign: string too long\n"));
			return;
		}
		
		type = String;
		strcpy(datum.string, p);
	} else if (isdigit(*p)) {
		char *endp;
		
		/* This can be either an integer or an IP address */
		datum.number = strtol(p, &endp, 0);
		if (*endp == 0) {
			type = Integer;
		} else {
			/* IP address */
			if ((datum.ipaddr = get_ipaddr(p)) != 0)
				type = Ipaddress;
			else {
				fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
				return;
			}
		} 
	} else if (*p == '{') {
		/* vector */
		fprintf(stderr, _("assign: vector type not supported yet\n"));
		return;
	} else if (strchr(p, '.')) {
		/* IP address */
		if ((datum.ipaddr = get_ipaddr(p)) != 0)
			type = Ipaddress;
		else {
			fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
			return;
		}
	} else {
		length = strlen(p);
		
		if (length > MAX_STRING) {
			fprintf(stderr, _("assign: string too long\n"));
			return;
		}
		
		type = String;
		strcpy(datum.string, p);
	}
	
	var = (Variable*)sym_install(vartab, s);
	var->type = type;
	var->datum = datum;
}

void
print_ident(buf, var)
	char *buf;
	Variable *var;
{
	switch (var->type) {
	case Undefined:
		sprintf(buf, _("UNDEFINED"));
		break;
	case Integer:
		sprintf(buf, "%d", var->datum.number);
		break;
	case Ipaddress:
		ipaddr2str(buf, var->datum.ipaddr);
		break;
	case String:
		sprintf(buf, "%s", var->datum.string);
		break;
	case Vector:
		break;
	}
}

void
print_pairs(fp, pair)
	FILE *fp;
	VALUE_PAIR *pair;
{
	for (; pair; pair = pair->next) {
		fprintf(fp, " %s = ", pair->name);
		switch (pair->type) {
		case PW_TYPE_STRING:
			fprintf(fp, "(STRING) %s", pair->strvalue);
			break;

		case PW_TYPE_INTEGER:
			fprintf(fp, "(INTEGER) %ld", pair->lvalue);
			break;

		case PW_TYPE_IPADDR:
			fprintf(fp, "(IP) %lx", pair->lvalue);
			break;
		
		case PW_TYPE_DATE:
			fprintf(fp, "(DATE) %ld", pair->lvalue);
			break;
			
		default:
			fprintf(fp, "(%d)", pair->type);
		}
		if (pair->next)
			fprintf(fp, ",");
		else
			fprintf(fp, " ");
/*		fprintf(fp, "\n");*/
	}
}

void
print(var)
	Variable *var;
{
	char buf[DOTTED_QUAD_LEN];
	if (!var)
		return;
	switch (var->type) {
	case Undefined:
		printf("UNDEFINED");
		break;
	case Integer:
		printf("%d", var->datum.number);
		break;
	case Ipaddress:
		printf("%s", ipaddr2str(buf, var->datum.ipaddr));
		break;
	case String:
		printf("%s", var->datum.string);
		break;
	case Vector:
		printf("{");
		print_pairs(stdout, var->datum.vector);
		printf("}");
		break;
	case Builtin:
		var->datum.builtin.print();
		break;
	}
}


/*
 *	Print usage message and exit.
 */
static char usage_str[] =
"usage: radtest [options]\n"
"Options are\n"
#ifdef HAVE_GETOPT_LONG
"    -a, --assign VARIABLE=VALUE  Assign a VALUE to a VARIABLE\n"
"    -d, --config-directory dir   Specify alternate configuration directory\n"
"                                 (default " RADIUS_DIR ")\n"
"    -p, --port PORT-NUMBER       Set RADIUS authentication port to PORT-NUMBER\n"
"    -q, --quick                  Quick mode\n"
"    -r, --retry NUMBER           Set number of retries\n"
"    -s, --server                 Set server name\n"
"    -t, --timeout NUMBER         Set timeout in seconds\n"
"    -v, --verbose                Verbose mode\n"
"    -x, --debug DEBUG-LEVEL      Set debugging level\n"
"    -h, --help                   Display this help and exit\n"
"    -V, --version                Show program version\n"
"    -L, --license                Display GNU license\n";
#else
"    -a VARIABLE=VALUE          Assign a VALUE to a VARIABLE\n"
"    -d dir                     Specify alternate configuration directory\n"
"                               (default " RADIUS_DIR ")\n"
"    -p PORT-NUMBER             Set RADIUS authentication port to PORT-NUMBER\n"
"    -q                         Quick mode\n"
"    -r NUMBER                  Set number of retries\n"
"    -s SERVER                  Set server name\n"
"    -t NUMBER                  Set timeout in seconds\n"
"    -v                         Verbose mode\n"
"    -x DEBUG-LEVEL             Set debugging level\n"
"    -h                         Display this help and exit\n"
"    -V                         Show program version\n"
"    -L                         Display GNU license\n";
#endif

void
print_usage()
{
	fprintf(stderr, usage_str);
	exit(1);
}

void
print_version()
{
	fprintf(stderr,
		_("radtest version %s\n"), VERSION);
	exit(0);
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
print_license()
{
	printf(_("This is radtest version %s\n"), VERSION);
	printf("%s: Copyright 1999,2000 Sergey Poznyakoff\n", progname);
	printf("\nThis program is part of GNU Radius\n");
	printf("%s", license_text);
	exit(0);
}
