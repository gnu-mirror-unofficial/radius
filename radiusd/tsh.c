/* This file is part of GNU Radius.
   Copyright (C) 2003 Free Software Foundation
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
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
#include <radargp.h>
#include <radutmp.h>
#include <rewrite.h>
#include <argcv.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#ifdef USE_SQL
# include <radsql.h>
#endif
#include <timestr.h>


static int interactive;

static void tsh_help(int argc, char **argv);
static void tsh_query_nas(int argc, char **argv);
#ifdef USE_SERVER_GUILE
static void tsh_guile(int argc, char **argv);
#endif
static void tsh_run_rewrite(int argc, char **argv);
static void tsh_source_rewrite(int argc, char **argv);
static void tsh_timespan(int argc, char **argv);
static void tsh_debug(int argc, char **argv);
static void tsh_quit(int argc, char **argv);

typedef void (*tsh_command) (int argc, char **argv);

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
	{"r", "run-rewrite", N_("FUNCTION(args..)"),
	 N_("Run given Rewrite function"), tsh_run_rewrite},
	{"s", "source", N_("FILE"),
	 N_("Source the given Rewrite file"), tsh_source_rewrite},
	{"t", "timespan", N_("TIMESPAN [DOW [HH [MM]]]"),
	 N_("Check the timespan interval"), tsh_timespan},
	{"d", "debug", N_("LEVEL"), N_("Set debugging level"), tsh_debug},
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
tsh_help(int argc, char **argv)
{
	struct command_table *cp;
	int n;
	
	for (cp = command_table; cp->shortname; cp++) {
		int len = strlen(cp->shortname);
		if (len == strlen(cp->longname))
			n = printf("%s", cp->longname);
		else 
			n = printf("(%*.*s)%s", len, len, cp->longname,
				   cp->longname + len);
		if (cp->usage)
			n += printf(" %s", cp->usage);
		print_doc(n, gettext(cp->doc));
	}
}

/* query-nas NAS LOGIN SID PORT [IP] */
static void
tsh_query_nas(int argc, char **argv)
{
	NAS *nas;
	struct radutmp ut;

	if (argc < 5 || argc > 6) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	nas = nas_lookup_name(argv[1]);
	if (!nas) {
		fprintf(stderr, _("%s: unknown nas\n"), argv[0]);
		return;
	}

	ut.nas_address = nas->ipaddr;

	strncpy(ut.orig_login, argv[2], sizeof(ut.orig_login));
	strncpy(ut.session_id, argv[3], sizeof(ut.session_id));
	ut.nas_port = atoi(argv[4]);
	if (argc == 6)
		ut.framed_address = ip_strtoip(argv[5]);
	printf("%d\n", checkrad(nas, &ut));
}

#ifdef USE_SERVER_GUILE
static void
tsh_guile(int argc ARG_UNUSED, char **argv ARG_UNUSED)
{
	scheme_read_eval_loop();
}
#endif

static void
tsh_run_rewrite(int argc, char **argv)
{
	char *str;
	Datatype type;
	Datum datum;

	if (argc < 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	argcv_string(argc - 1, argv + 1, &str);

	if (interpret(str, NULL, &type, &datum))
		printf("?\n");
	else {
		switch (type) {
		case Integer:
			printf("%d (%u)", datum.ival,
			       (unsigned) datum.ival);
			break;

		case String:
			printf("%s", datum.sval);
			break;

		case Undefined:
			printf(_("Undefined"));
			break;

		default:
			abort();
		}
		printf("\n");
	}
	free(str);
}

static void
tsh_source_rewrite(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	printf("%d\n", parse_rewrite(argv[1]));
}

/* timespan TIMESPAN [DOW [HH [MM]]] */
static void
tsh_timespan(int argc, char **argv)
{
        time_t          t;
        TIMESPAN       *ts;
        char           *p;
        unsigned       rest;
        int i;
        struct tm tm;

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
                tm.tm_wday = 0;
                tm.tm_mday += atoi(argv[2]);
                tm.tm_yday += atoi(argv[2]);
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
tsh_debug(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			_("%s: wrong number of arguments\n"), argv[0]);
		return;
	}
	while (--argc)
		set_debug_levels(*++argv);
}

static void
tsh_quit(int argc ARG_UNUSED, char **argv ARG_UNUSED)
{
	exit(0);
}


#ifdef WITH_READLINE
static char **tsh_command_completion __P((char *cmd, int start, int end));
static char *tsh_command_generator __P((const char *text, int state));
#else
char *readline(const char *prompt);
#endif

static volatile int _interrupted;

void
tsh_clear_interrupt()
{
	_interrupted = 0;
}

int
tsh_got_interrupt()
{
	int rc = _interrupted;
	_interrupted = 0;
	return rc;
}

static int
tsh_getc(FILE * stream)
{
	unsigned char c;

	while (1) {
		if (read(fileno(stream), &c, 1) == 1)
			return c;
		if (errno == EINTR) {
			if (_interrupted)
				break;
			/* keep going if we handled the signal */
		} else
			break;
	}
	return EOF;
}

void
tsh_readline_init()
{
	if (!interactive)
		return;

#ifdef WITH_READLINE
	rl_readline_name = "radiusd";
	rl_attempted_completion_function =
	    (CPPFunction *) tsh_command_completion;
	rl_getc_function = tsh_getc;
#endif
}

char *
tsh_readline_internal()
{
	char *line;
	char *p;
	size_t alloclen, linelen;

	p = line = calloc(1, 255);
	if (!p) {
		fprintf(stderr, _("Not enough memory\n"));
		abort();
	}
	alloclen = 255;
	linelen = 0;
	for (;;) {
		size_t n;

		p = fgets(p, alloclen - linelen, stdin);

		if (p)
			n = strlen(p);
		else if (_interrupted) {
			free(line);
			return NULL;
		} else
			n = 0;

		linelen += n;

		/* Error.  */
		if (linelen == 0) {
			free(line);
			return NULL;
		}

		/* Ok.  */
		if (line[linelen - 1] == '\n') {
			line[linelen - 1] = '\0';
			return line;
		} else {
			char *tmp;
			alloclen *= 2;
			tmp = realloc(line, alloclen);
			if (tmp == NULL) {
				free(line);
				return NULL;
			}
			line = tmp;
			p = line + linelen;
		}
	}
}

char *
tsh_readline(const char *prompt)
{
	if (interactive)
		return readline(prompt);
	return tsh_readline_internal();
}

#ifdef WITH_READLINE

/*
 * readline tab completion
 */
char **
tsh_command_completion(char *cmd, int start ARG_UNUSED, int end ARG_UNUSED)
{
	if (start == 0)
		return rl_completion_matches(cmd, tsh_command_generator);
	return NULL;
}

/*
 * more readline
 */
char *
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
#else

char *
readline(const char *prompt)
{
	if (prompt) {
		printf("%s", prompt);
		fflush(stdout);
	}

	return tsh_readline_internal();
}
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
	struct command_table *cp = tsh_find_entry(name);
	return cp ? cp->handler : NULL;
}

static void
tsh_run_function(int argc, char **argv)
{
	tsh_command fp = tsh_find_function(argv[0]);
	if (fp)
		fp(argc, argv);
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
	if (argcv_get(cmd, "=", &argc, &argv) == 0) {
		tsh_run_function(argc, argv);
#ifdef WITH_READLINE
		add_history(cmd);
#endif
	}
	argcv_free(argc, argv);
}

int
tsh()
{
	char *cmd;

	interactive = isatty(fileno(stdin));
	if (interactive)
		printf("** TEST SHELL **\n");
	tsh_readline_init();
	while ((cmd = tsh_readline("test shell> ")) != NULL) {
		tsh_run_command(cmd);
		free(cmd);
	}
}