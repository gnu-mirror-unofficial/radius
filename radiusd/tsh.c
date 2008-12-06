/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2005,2007,2008 Free Software Foundation
  
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
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#ifdef HAVE_READLINE_READLINE_H
# include <readline/readline.h>
#endif

#include <radiusd.h>
#include <radius/radargp.h>
#include <radius/radutmp.h>
#include <rewrite.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <timestr.h>

static int interactive;
static grad_request_t test_req;
static char *tsh_ps1 = "(radiusd) ";
static char *tsh_ps2 = "[radiusd] ";

static char *tsh_readline(const char *prompt);

static void tsh_help(int argc, char **argv, char *cmd);
static void tsh_query_nas(int argc, char **argv, char *cmd);
#ifdef USE_SERVER_GUILE
static void tsh_guile(int argc, char **argv, char *cmd);
#endif
static void tsh_run_rewrite(int argc, char **argv, char *cmd);
static void tsh_source_rewrite(int argc, char **argv, char *cmd);
static void tsh_timespan(int argc, char **argv, char *cmd);
static void tsh_debug(int argc, char **argv, char *cmd);
static void tsh_quit(int argc, char **argv, char *cmd);
static void tsh_req_define(int argc, char **argv, char *cmd);
static void tsh_req_print(int argc, char **argv, char *cmd);
static void tsh_rewrite_stack(int argc, char **argv, char *cmd);

typedef void (*tsh_command) (int argc, char **argv, char *cmd);

struct command_table {
	char *shortname;
	char *longname;
	char *usage;
	char *doc;
	tsh_command handler;
} command_table[] = {
	{"h", "help", NULL, N_("Print this help screen"), tsh_help},
	{"q", "query-nas", N_("NAS LOGIN SID PORT [IP]"),
	 N_("Query the given NAS"), tsh_query_nas},
#ifdef USE_SERVER_GUILE
	{"g", "guile", NULL, N_("Enter Guile"), tsh_guile},
#endif
	{"rs", "rewrite-stack", N_("[NUMBER]"),
	 N_("Print or set the Rewrite stack size"),
	 tsh_rewrite_stack},
	{"r", "run-rewrite", N_("FUNCTION(args..)"),
	 N_("Run given Rewrite function"), tsh_run_rewrite},
	{"s", "source", N_("FILE"),
	 N_("Source the given Rewrite file"), tsh_source_rewrite},
	{"t", "timespan", N_("TIMESPAN [DOW [HH [MM]]]"),
	 N_("Check the timespan interval"), tsh_timespan},
	{"d", "debug", N_("LEVEL"), N_("Set debugging level"), tsh_debug},
	{"rd", "request-define", N_("[PAIR [,PAIR]]"), N_("Define a request"),
	 tsh_req_define },
	{"rp", "request-print", NULL, N_("Print the request"),
	 tsh_req_print},
	{"quit", "quit", NULL, N_("Quit the shell"), tsh_quit},
	{NULL}
};

/* Functions for printing help information */

#define OPT_DOC_COL  39		/* column in which option text starts */
#define RMARGIN      79		/* right margin used for wrapping */

static void
print_doc (int n, char *s)
{
	if (n > OPT_DOC_COL) {
		putchar('\n');
		n = 0;
	}
	
	do {
		char *p;
		char *space = NULL;
		
		for (; n < OPT_DOC_COL; n++)
			putchar(' ');

		for (p = s; *p && p < s + (RMARGIN - OPT_DOC_COL); p++)
			if (isspace(*p))
				space = p;
		
		if (!space || p < s + (RMARGIN - OPT_DOC_COL)) {
			printf("%s", s);
			s += strlen (s);
		} else {
			for (; s < space; s++)
				putchar(*s);
			for (; *s && isspace(*s); s++)
				;
		}
		putchar('\n');
		n = 1;
	} while (*s);
}
      

static void
tsh_help(int argc, char **argv, char *cmd ARG_UNUSED)
{
	struct command_table *cp;
	int n;
	
	for (cp = command_table; cp->shortname; cp++) {
		int len = strlen(cp->shortname);

		n = printf("%-8.8s%s", cp->shortname, cp->longname);
		if (cp->usage)
			n += printf(" %s", cp->usage);
		print_doc(n, gettext(cp->doc));
	}
}

/* query-nas NAS LOGIN SID PORT [IP] */
static void
tsh_query_nas(int argc, char **argv, char *cmd ARG_UNUSED)
{
	grad_nas_t *nas;
	struct radutmp ut;

	if (argc < 5 || argc > 6) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	nas = grad_nas_lookup_name(argv[1]);
	if (nas) {
		if (nas->netdef.netmask != 0xffffffffL) {
			fprintf(stderr, _("%s is a network name\n"), argv[1]);
			return;
		}
		ut.nas_address = nas->netdef.ipaddr;
	} else {
		ut.nas_address = grad_ip_gethostaddr(argv[0]);
		if (!ut.nas_address) {
			fprintf(stderr, _("%s: unknown nas\n"), argv[0]);
			return;
		}
	}

	strncpy(ut.orig_login, argv[2], sizeof(ut.orig_login));
	strncpy(ut.session_id, argv[3], sizeof(ut.session_id));
	ut.nas_port = atoi(argv[4]);
	if (argc == 6)
		ut.framed_address = grad_ip_strtoip(argv[5]);
	printf("%d\n", checkrad(nas, &ut));
}

#ifdef USE_SERVER_GUILE
static void
tsh_guile(int argc ARG_UNUSED, char **argv ARG_UNUSED, char *cmd ARG_UNUSED)
{
	scheme_read_eval_loop();
}
#endif

static void
tsh_rewrite_stack(int argc, char **argv, char *cmd)
{
	if (argc > 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	if (argc == 1) 
		printf("%lu\n", (long unsigned) rewrite_get_stack_size());
	else {
		char *p;
		size_t n = strtoul(argv[1], &p, 0);
		if (*p) 
			fprintf(stderr,
				_("%s: argument is not a number\n"), argv[0]);
		else
			rewrite_set_stack_size(n);
	}
}

static void
tsh_run_rewrite(int argc, char **argv, char *cmd)
{
	grad_value_t val;
	
	if (argc < 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}

	while (*cmd && isspace(*cmd))
		cmd++;
	while (*cmd && !isspace(*cmd))
		cmd++;

	if (rewrite_interpret(cmd, &test_req, &val))
		printf("?\n");
	else {
		switch (val.type) {
		case Integer:
			printf("%d (%u)", val.datum.ival,
			       (unsigned) val.datum.ival);
			break;

		case String:
			printf("%s", val.datum.sval.data);
			break;

		case Undefined:
			printf(_("Undefined"));
			break;

		default:
			abort();
		}
		grad_value_free(&val);
		printf("\n");
	}
}

static void
tsh_source_rewrite(int argc, char **argv, char *cmd ARG_UNUSED)
{
	if (argc != 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	printf("%d\n", rewrite_load_module(argv[1]));
}

/* timespan TIMESPAN [DOW [HH [MM]]] */
static void
tsh_timespan(int argc, char **argv, char *cmd ARG_UNUSED)
{
        time_t          t;
        TIMESPAN       *ts;
        char           *p;
        unsigned       rest;
        int i;
        struct tm tm;
	int diff, dow;
	
	if (argc < 2 || argc > 5) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}

        time(&t);
        localtime_r(&t, &tm);
        
        switch (argc) {
        default:
		return;
        case 5:
                tm.tm_min = atoi(argv[4]);
        case 4:
                tm.tm_hour = atoi(argv[3]);
        case 3:
		dow = atoi(argv[2]);
		diff = dow - tm.tm_wday;
		tm.tm_wday = dow;
		tm.tm_mday += diff;
		tm.tm_yday += diff;
                t = mktime(&tm);
                break;
        case 2:
                break;
        }

        printf("ctime: %s", ctime(&t));
        
        if (ts_parse(&ts, argv[1], &p)) {
                printf("bad timestring near %s\n", p);
        } else {
		int l = ts_match(ts, &t, &rest);
		if (l == 0)
			printf("inside %s: %d seconds left\n", argv[1], rest);
		else
			printf("OUTSIDE %s: %d seconds to wait\n",
			       argv[1], rest);
	}
}

static void
tsh_debug(int argc, char **argv, char *cmd ARG_UNUSED)
{
	if (argc < 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	while (--argc)
		grad_set_debug_levels(*++argv);
}

static void
tsh_req_define(int argc, char **argv, char *cmd)
{
	char *errp;
	grad_avp_t *vp = NULL;
	
	if (argc > 1) {
		while (*cmd && isspace(*cmd))
			cmd++;
		while (*cmd && !isspace(*cmd))
			cmd++;

		if (userparse(cmd, &vp, &errp)) {
                        grad_log(GRAD_LOG_ERR, "%s", errp);
			return;
		}
	} else {
		if (interactive)
			printf(_("Enter the pair list. End with end of file\n"));
		while ((cmd = grad_readline(tsh_ps2)) != NULL
		       && cmd[0]) {
			if (userparse(cmd, &vp, &errp)) {
				grad_log(GRAD_LOG_ERR, "%s", errp);
				free(cmd);
				grad_avl_free(vp);
				return;
			}
			free(cmd);
		}
	}
	grad_avl_free(test_req.avlist);
	test_req.avlist = vp;
}

static void
tsh_req_print(int argc, char **argv, char *cmd)
{
	grad_avl_fprint(stdout, "    ", 1, test_req.avlist);
}


static void
tsh_quit(int argc ARG_UNUSED, char **argv ARG_UNUSED, char *cmd ARG_UNUSED)
{
	grad_write_history_file();
	exit(0);
}


#ifdef WITH_READLINE

/*
 * more readline
 */
static char *
tsh_command_generator(const char *text, int state)
{
	static int i, len;
	const char *name;

	if (!state) {
		i = 0;
		len = strlen(text);
	}

	while ((name = command_table[i].longname)) {
		if (strlen(command_table[i].shortname) > strlen(name))
			name = command_table[i].shortname;
		i++;
		if (strncmp(name, text, len) == 0)
			return (strdup(name));
	}

	return NULL;
}

/*
 * readline tab completion
 */
static char **
tsh_command_completion(char *cmd, int start ARG_UNUSED, int end ARG_UNUSED)
{
	if (start == 0)
		return rl_completion_matches(cmd, tsh_command_generator);
	return NULL;
}
#else
# define tsh_command_completion NULL
#endif

static struct command_table *
tsh_find_entry(char *cmd)
{
	int len = strlen(cmd);
	struct command_table *cp;

	for (cp = command_table; cp->shortname; cp++) {
		int ll = 0, sl = 0;

		sl = strlen(cp->shortname);
		ll = strlen(cp->longname);
		if ((sl > ll && !strncmp(cp->shortname, cmd, sl))
		    || (sl == len && !strcmp(cp->shortname, cmd))
		    || (sl < len && !strncmp(cp->longname, cmd, len)))
			return cp;
	}
	return NULL;
}

static tsh_command
tsh_find_function(char *name)
{
	struct command_table *cp;
	if (name[0] == '?' && name[1] == 0)
		name = "help";
	cp = tsh_find_entry(name);
	return cp ? cp->handler : NULL;
}

static void
tsh_run_function(int argc, char **argv, char *cmd)
{
	tsh_command fp;

	if (argc == 0)
		return;
	fp = tsh_find_function(argv[0]);
	if (fp)
		fp(argc, argv, cmd);
	else
		fprintf(stderr, _("Bad command\n"));
}

static void
tsh_run_command(char *cmd)
{
	int argc = 0;
	char **argv;
	while (*cmd && isspace(*cmd))
		cmd++;
	if (!cmd || cmd[0] == '#')
		return;
	if (grad_argcv_get(cmd, "=", NULL, &argc, &argv) == 0) {
		grad_add_history(cmd);
		tsh_run_function(argc, argv, cmd);
	}
	grad_argcv_free(argc, argv);
}

int
tsh()
{
	char *cmd;

	interactive = isatty(fileno(stdin));
	if (interactive)
		printf("** TEST SHELL **\n");
	grad_readline_init("radiusd", interactive, tsh_command_completion);
	grad_read_history_file();
	while ((cmd = grad_readline(tsh_ps1)) != NULL) {
		tsh_run_command(cmd);
		free(cmd);
	}
	tsh_quit(0, NULL, NULL);
}
