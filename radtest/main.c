/* This file is part of GNU RADIUS.
   Copyright (C) 2000, 2001, Sergey Poznyakoff
 
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
#include <getopt1.h>
#include <radius.h>
#include <radpaths.h>
#include <radclient.h>
#include <log.h>
#include <radtest.h>

#define OPTSTR "a:d:f:hLp:qr:s:t:vx:V"
struct option longopt[] = {
	"assign", required_argument, 0, 'a',
	"debug", required_argument, 0, 'x',
	"directory", required_argument, 0, 'd',
	"file", required_argument, 0, 'f',
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

Symtab *vartab;
char *radius_dir = RADIUS_DIR;
int verbose;
extern int radclient_debug;
RADCLIENT       *radclient;
char *progname;
int reply_code;
VALUE_PAIR *reply_list;
int debug_flag = 0;
int abort_on_failure = 0;

void init_symbols();
static void print_usage();
static void print_license();
static void print_version();
static void assign(char *);

int x_argmax;
int x_argc;
char **x_argv;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	int quick = 0;
	char *filename = NULL;
	char *p;
	char *server = NULL;
	int retry = 0;
	int timeout = 0;
	
	app_setup();
	initlog(argv[0]);
	init_symbols();

	opterr = 0;
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
			quick++;
			break;
		case 'r':
			retry = strtol(optarg, NULL, 0);
			break;
		case 's':
			server = optarg;
			break;
		case 'f':
			filename = optarg;
			break;
		case 't':
			timeout = strtol(optarg, NULL, 0);
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
			if (filename
			    && argv[optind-1][0] == '-'
			    && argv[optind-1][1] == '-'
			    && (p = strchr(argv[optind-1], '=')) != NULL
			    && !(p > argv[optind-1] && p[-1] == '\\')) {
			    assign(argv[optind-1]+2);
			} else {
				print_usage();
				return 1;
			}
		}
	}

	set_yydebug();
	radpath_init();
	if (dict_init()) {
		radlog(L_ERR, _("error reading dictionary file"));
		return 1;
	}
	radclient = radclient_alloc(!quick, 0, 0);
	
	if (!radclient)
		return 1;

	if (timeout)
		radclient->timeout = timeout;
	if (retry)
		radclient->retries = retry;
	if (server) {
		SERVER serv;
		int i, argc;
		char **argv;

		if (argcv_get(server, ":", &argc, &argv)) {
			radlog(L_ERR, "can't parse server definition");
			exit(1);
		}

		if (argc < 3) {
			radlog(L_ERR, "no shared secret for the server");
			exit(1);
		}

		memset(&serv, 0, sizeof serv);
		serv.name = "default";
		for (i = 0; i < argc; i++) {
			switch (i) {
			case 0:
				serv.addr = get_ipaddr(argv[i]);
				if (!serv.addr) {
					radlog(L_ERR,
					     "bad IP address or host name: %s",
					       argv[i]);
					exit(1);
				}
				break;
			case 2:
				serv.secret = argv[i];
				break;
			case 4:
				serv.port[0] = strtol(argv[i], &p, 0);
				if (*p) {
					radlog(L_ERR,
					       "bad port number %s",
					       argv[i]);
					break;
				}
				break;
			case 6:
				serv.port[1] = strtol(argv[i], &p, 0);
				if (*p) {
					radlog(L_ERR,
					       "bad port number %s",
					       argv[i]);
					break;
				}
				break;
			default:
				if (argv[i][0] != ':') {
					radlog(L_ERR,
					       "bad separator near %s",
					       argv[i]);
					exit(1);
				}
				break;
			}
		}

		if (argc < 4)
			serv.port[0] = DEF_AUTH_PORT;
		if (argc < 6)
			serv.port[1] = DEF_ACCT_PORT;
		radclient->first_server =
			radclient_append_server(radclient->first_server,
						radclient_alloc_server(&serv));
		argcv_free(argc, argv);
	}

	if (!radclient->first_server) {
		radlog(L_ERR,
		       "No servers specfied. Use -s option.\n");
		exit(1);
	}
	
	argc -= optind;
	argv += optind;

	x_argv = emalloc(sizeof(x_argv[0]) * argc);
	x_argc = 0;
	x_argmax = argc;
	x_argv[x_argc++] = filename;

	for (; argc; argc--, argv++) {
		if ((p = strchr(*argv, '=')) != NULL &&
		    !(p > *argv && p[-1] == '\\')) 
			assign(*argv);
		else 
			x_argv[x_argc++] = *argv;
	}
	x_argv[x_argc++] = NULL;
	
	if (open_input(filename))
		return 1;
	return yyparse();
}

void
init_symbols()
{
	Variable *var;
	
	vartab = symtab_create(sizeof(Variable), NULL);
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

	type = parse_datum(p, &datum);
	if (type == Undefined)
		return;
	var = (Variable*)sym_install(vartab, s);
	var->type = type;
	var->datum = datum;
}

int
parse_datum(p, dp)
	char *p;
	union datum *dp;
{
	int type = Undefined;
	int length;
	
	if (*p == '"') {
		length = strlen(++p);
		if (length == 0 || p[length-1] != '"') {
			fprintf(stderr, _("assign: missing closing quote\n"));
			return Undefined;
		}
		p[length-1] = 0;
		
		type = String;
		dp->string = make_string(p);
	} else if (isdigit(*p)) {
		char *endp;
		
		/* This can be either an integer or an IP address */
		dp->number = strtol(p, &endp, 0);
		if (*endp == 0) {
			type = Integer;
		} else {
			/* IP address */
			if ((dp->ipaddr = get_ipaddr(p)) != 0)
				type = Ipaddress;
			else {
				fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
				return Undefined;
			}
		} 
	} else if (strchr(p, '.')) {
		/* IP address */
		if ((dp->ipaddr = get_ipaddr(p)) != 0)
			type = Ipaddress;
		else {
			fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
			return Undefined;
		}
	} else {
		type = String;
		dp->string = make_string(p);
	}
	return type;
}

char *
print_ident(var)
	Variable *var;
{
	char buf[64];
	switch (var->type) {
	case Undefined:
		return make_string("UNDEFINED");
		break;
	case Integer:
		sprintf(buf, "%d", var->datum.number);
		return make_string(buf);
	case Ipaddress:
		ipaddr2str(var->datum.ipaddr, buf);
		return make_string(buf);
	case String:
		return dup_string(var->datum.string);
		break;
	case Vector:
		return make_string("VECTOR");
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
		case TYPE_STRING:
			fprintf(fp, "(STRING) %s", pair->strvalue);
			break;

		case TYPE_INTEGER:
			fprintf(fp, "(INTEGER) %ld", pair->lvalue);
			break;

		case TYPE_IPADDR:
			fprintf(fp, "(IP) %lx", pair->lvalue);
			break;
		
		case TYPE_DATE:
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
var_print(var)
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
		printf("%s", ipaddr2str(var->datum.ipaddr, buf));
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

void
var_free(var)
	Variable *var;
{
	if (var->name)
		return; /* named variables are not freed */
	switch (var->type) {
	case String:
		free_string(var->datum.string);
		break;
	case Vector:
		avl_free(var->datum.vector);
		break;
	}
}

void
radtest_send(port, code, var)
	int port;
	int code;
	Variable *var;
{
	RADIUS_REQ *auth;
	
	if (reply_list)
		avl_free(reply_list);
	reply_list = NULL;
	reply_code = 0;
	
	if (var->type != Vector) {
		parse_error(_("wrong datatype: expected vector"));
		return;
	}

	auth = radclient_send(radclient,
			      port,
			      code, var->datum.vector);
	if (!auth)
		return;

	reply_code = auth->code;
	var = (Variable*)sym_lookup(vartab, "REPLY_CODE");
	var->type = Integer;
	var->datum.number = reply_code;

	reply_list = avl_dup(auth->request);
	var = (Variable*)sym_lookup(vartab, "REPLY");
	var->type = Vector;
	var->datum.vector = NULL;
	var->datum.vector = reply_list;
	radreq_free(auth);
}

/* FIXME: duplicated in radiusd/files.c */
int
comp_op(op, result)
	int op;
	int result;
{
	switch (op) {
	default:
	case OPERATOR_EQUAL:
		if (result != 0)
			return -1;
		break;

	case OPERATOR_NOT_EQUAL:
		if (result == 0)
			return -1;
		break;

	case OPERATOR_LESS_THAN:
		if (result >= 0)
			return -1;
		break;

	case OPERATOR_GREATER_THAN:
		if (result <= 0)
			return -1;
		break;
		    
	case OPERATOR_LESS_EQUAL:
		if (result > 0)
			return -1;
		break;
			
	case OPERATOR_GREATER_EQUAL:
		if (result < 0)
			return -1;
		break;
	}
	return 0;
}

int
compare_lists(reply, sample)
	VALUE_PAIR *reply, *sample;
{
	int result = 0;
	
	for (; sample && result == 0; sample = sample->next) {
		VALUE_PAIR *p;

		if (sample->attribute > 255)
			continue;
		for (p = reply; p && p->attribute != sample->attribute;
		     p = p->next)
			;
		if (!p)
			return -1;
		switch (p->type) {
		case TYPE_STRING:
			result = strcmp(sample->strvalue, p->strvalue);
			break;
		case TYPE_INTEGER:
		case TYPE_IPADDR:
			result = sample->lvalue - p->lvalue;
			break;
		default:
			result = -1;
		}
		result = comp_op(sample->operator, result);
	}
	return result;
}

/*
 *	Print usage message and exit.
 */
static char usage_str[] =
"usage: radtest [options]\n"
"Options are\n"
"    -a, --assign VARIABLE=VALUE  Assign a VALUE to a VARIABLE\n"
"    -d, --config-directory dir   Specify alternate configuration directory\n"
"                                 (default " RADIUS_DIR ")\n"
"    -f, --file FILE              Read input from FILE. When this option is\n"
"                                 used, all unknown options in the form\n"
"                                 --VAR=VALUE are treated as variable\n"
"                                 assignments\n"
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

void
print_usage()
{
	printf(usage_str);
	exit(1);
}

void
print_version()
{
	printf(_("radtest version %s\n"), VERSION);
        printf("\nReport bugs to <%s>\n", bug_report_address);
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
	printf("%s: Copyright 1999,2000,2001 Sergey Poznyakoff\n", progname);
	printf("\nThis program is part of GNU Radius\n");
	printf("%s", license_text);
	exit(0);
}
