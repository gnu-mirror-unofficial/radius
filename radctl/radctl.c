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
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif

#include <radiusd.h>
#include <radutmp.h>
#include <radclient.h>
#define CNTL_STATE_DECL
#include <radctl.h>

#define OPTSTR "d:hLu:p:s:v?"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {
	"directory", required_argument, 0, 'd',
	"license",   no_argument,       0, 'L',
	"server",    required_argument, 0, 's',
	"user",      required_argument, 0, 'u',
	"password",  optional_argument, 0, 'p',
	"verbose",   no_argument,       0, 'v',
	"help",      no_argument,       0, 'h',
	0
};
#else
# define longopt 0
# define getopt_long(ac,av,os,lo,li) getopt(ac,av,os)
#endif

static void usage();
static void license();
int collect_args(int argc, char **argv);
int moreinput();
void radctl();
void radctl_decode(AUTH_REQ *auth);
char * getstr_noecho(char *prompt, char *arg);
char * get_username();
void dashcmd(char *cmd, char *arg);
void bye();
void source_rc();

int             verbose;
char            *hostname;
char            *user;
char            *password;
char		vector[AUTH_VECTOR_LEN];

static char     *prompt = "> ";
static char     *filename;
static int      line_no;
static char     input_buffer[216];
static char     *input_ptr;
RADCLIENT       *radclient;

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
		case 'd':
			radius_dir = optarg;
			break;
		case 's':
			hostname = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'L':
			license();
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
			/*NOTREACHED*/
	}

	if (!user && (user = get_username()) == NULL) 
		return 1;
	password = getstr_noecho(_("Password"), password);
		       
	radpath_init();
	if (dict_init(NULL) < 0) {
		return -1;
	}
	radclient = radclient_init(radius_dir);
	if (!radclient)
		return -1;
	
	radclient_delete_server(radclient, NULL);
	if (hostname && radclient_find_server(radclient, hostname) == 0) {
		radlog(L_ERR, _("unknown server: %s"), hostname);
		hostname = NULL;
	}
	if (!hostname)
		hostname = radclient->server->name;
	radclient_add_server(radclient, hostname);
	
	
	if (collect_args(argc - optind, argv + optind)) {
		filename = _("<command line>");
		line_no = 0;
		radctl();
	} else {
		filename = _("<teletype>");
		line_no = 0;
		while (moreinput(stdin))
			radctl();
		bye();
	}
	return 0;
}

void
change_hostname(new_name)
	char *new_name;
{
	if (radclient_find_server(radclient, new_name) == 0) {
		radlog(L_ERR, _("unknown hostname: %s"), new_name);
		return;
	}
	radclient_delete_server(radclient, NULL);
	radclient_add_server(radclient, new_name);
}


int
collect_args(argc, argv)
	int argc;
	char **argv;
{
	char *p;
	int len;
	
	p = input_buffer;
	while (argc--) {
		len = strlen(*argv);
		if (p + len + 1 >= input_buffer + sizeof input_buffer) {
			radlog(L_ERR, _("argument command string too long: truncated"));
			break;
		}
		strncpy(p, *argv, len);
		p += len;
		*p++ = ' ';
		++argv;
	}
	*p = 0;
	input_ptr = input_buffer;
	return input_ptr[0];
}

void
bye()
{
	printf(_("bye\n"));
	exit(0);
}

void
source_rc(dir, file)
	char *dir;
	char *file;
{
	FILE *fp;
	char *path = mkfilename(dir, file);

	if ((fp = fopen(path, "r")) == NULL) {
		if (errno != ENOENT)
			radlog(L_ERR|L_PERROR,
			       _("can't open `%s' for reading"),
			       path);
		efree(path);
		return;
	}
	filename = path;
	line_no = 0;
	while (moreinput(fp))
		radctl();
	fclose(fp);
	efree(path);
}

int
moreinput(fp)
	FILE *fp;
{
	if (isatty(fileno(fp)))
		printf("%s", prompt);
	input_ptr = fgets(input_buffer, sizeof(input_buffer), fp);
	line_no++;
	return input_ptr != NULL;
}

void
radctl()
{
	char *statep, *argp;
	VALUE_PAIR *pairlist;
	AUTH_REQ   *req;
	
	if (!input_ptr)
		return;
	
	while (*input_ptr && isspace(*input_ptr))
		input_ptr++;
	if (*input_ptr == 0 || *input_ptr == '#')
		return;
	
	statep = input_ptr;
	while (*input_ptr && !isspace(*input_ptr))
		input_ptr++;
	if (*input_ptr) {
		*input_ptr++ = 0;
		while (*input_ptr && isspace(*input_ptr))
			input_ptr++;
		argp = input_ptr;
		while (*input_ptr && !isspace(*input_ptr))
			input_ptr++;
		if (*input_ptr)
			*input_ptr++ = 0;
	} else
		argp = NULL;

	if (argp && *argp == 0)
		argp = NULL;
	
	if (statep[0] == '-') {
		dashcmd(statep, argp);
		return;
	}

	pairlist = create_pair(DA_USER_NAME, strlen(user), user, 0);
	pairadd(&pairlist,
		create_pair(DA_PASSWORD, strlen(password), password, 0));
	pairadd(&pairlist,
		create_pair(DA_STATE, strlen(statep), statep, 0));
	if (argp)
		pairadd(&pairlist,
			create_pair(DA_CLASS, strlen(argp), argp, 0));

	req = radclient_send(radclient, 2, PW_AUTHENTICATION_REQUEST, pairlist);
	pairfree(pairlist);
	if (req) {
		radctl_decode(req);
		authfree(req);
	} else
		printf(_("no answer from %s\n"),
			 ip_hostname(radclient->first_server->addr));
}

void
radctl_decode(auth)
	AUTH_REQ *auth;
{
	VALUE_PAIR *pair;
	
	if (auth->code == PW_AUTHENTICATION_ACK)
		printf(_("OK\n"));
	else
		printf(_("ERROR\n"));

	for (pair = auth->request; pair; pair = pair->next) {
		if (pair->attribute == DA_REPLY_MESSAGE) 
			printf("%s", pair->strvalue);
	}
	printf("\n");
}

enum dash_command {
	CMD_HELP,
	CMD_QUIT,
	CMD_SERVER,
	CMD_VERBOSE,
	CMD_USER,
	CMD_PASSWORD,
};

struct keyword dash_kwd[] = {
	"-help",     CMD_HELP,
	"-?",        CMD_HELP,
	"-quit",     CMD_QUIT,
	"-q",        CMD_QUIT,
	"-s",        CMD_SERVER,
	"-server",   CMD_SERVER,
	"-verbose",  CMD_VERBOSE,
	"-v",        CMD_VERBOSE,
	"-user",     CMD_USER,
	"-u",        CMD_USER,
	"-password", CMD_PASSWORD,
	"-p",        CMD_PASSWORD,
	0
};

char *cmd_usage_str = N_(
"commands:\n"
"    -help or -?         display this help\n"
"    -q(uit)             quit the program\n"
"    -s(server)          change RADIUS server\n"
"    -verbose            toggle verbose mode\n"
"    -u(ser)             set user name\n"
"    -p(assword)         set user password\n");


void
dashcmd(s, arg)
	char *s;
	char *arg;
{
	extern int radclient_debug;
	
	if (s[1] == '-')
		s++;
	switch (xlat_keyword(dash_kwd, s, -1)) {
	case CMD_HELP:
		printf("%s", _(cmd_usage_str));
		break;
		
	case CMD_QUIT:
		bye();
		
	case CMD_SERVER:
		change_hostname(arg);
		break;
		
	case CMD_VERBOSE:
		verbose = !verbose;
		printf(_("radctl is now %s\n"),
		       verbose ? _("verbose") : _("silent"));
		radclient_debug = verbose;
		break;
		
	case CMD_USER:
		if (arg)
			user = estrdup(arg);
		else {
			char *p;
			
			p = get_username();
			if (!p) 
				printf(_("not changed\n"));
			else
				user = p;
		}
		break;
		
	case CMD_PASSWORD:
		password = getstr_noecho(_("Password"), arg);
		break;

	default:
		radlog(L_ERR, _("%s:%d: unknown command: %s"),
		       filename, line_no, s);
	}
}


static char usage_str[] =
#ifdef HAVE_GETOPT_LONG
N_(
"usage: radctl [options] [commands]\n"
"Options are:\n"
"    -d, --directory DIR          specify radius database directory\n"
"    -L, --license                display GNU license and exit\n"
"    -s, --server SERVERNAME      set RADIUS server name\n"
"    -u, --user USERNAME          set user name\n"
"    -p, --password TEXT          set user password\n"
"    -v, --verbose                be verbose on output\n"
"    -?, --help                   display this help\n")
#else
N_("usage: radctl [options] [commands]\n"
"Options are:\n"
"    -d DIR        specify radius database directory\n"
"    -L            display GNU license and exit\n"
"    -s SERVERNAME set RADIUS server name\n"
"    -u USERNAME   set user name\n"
"    -p TEXT       set user password\n"
"    -v            be verbose on output\n"
"    -?            display this help\n")
#endif
;

void
usage()
{
	printf(_(usage_str));
	exit(0);
}

char *
getstr_noecho(prompt, arg)
	char *prompt;
	char *arg;
{
	if (arg == NULL || strcmp(arg, ":") == 0) {
		printf("%s", prompt);fflush(stdout);
		arg = getpass(":");
	} 
	return estrdup(arg);
}


char *
get_username()
{
	char buffer[RUT_NAMESIZE+1];
	int len;
	
	printf(_("Username: "));
	fgets(buffer, sizeof(buffer), stdin);
	len = strlen(buffer);
	if (len <= 1)
		return NULL;
	if (buffer[len-1] == '\n')
		buffer[len-1] = 0;
	return estrdup(buffer);
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
