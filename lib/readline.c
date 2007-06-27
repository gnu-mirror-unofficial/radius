/* This file is part of GNU Radius.
   Copyright (C) 2003,2004,2007 Free Software Foundation
  
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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#ifdef HAVE_READLINE_READLINE_H
# include <readline/readline.h>
#endif
#include <common.h>

static volatile int _interrupted;
static int _interactive;

static void
grad_clear_interrupt()
{
	_interrupted = 0;
}

static int
grad_got_interrupt()
{
	int rc = _interrupted;
	_interrupted = 0;
	return rc;
}

static char *
grad_readline_internal(FILE *input)
{
	char *line;
	char *p;
	size_t alloclen, linelen;

	if (!input)
		input = stdin;
	
	p = line = calloc(1, 255);
	if (!p) {
		fprintf(stderr, _("Not enough memory\n"));
		abort();
	}
	alloclen = 255;
	linelen = 0;
	for (;;) {
		size_t n;

		p = fgets(p, alloclen - linelen, input);

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

#ifndef WITH_READLINE
static FILE *rl_instream;

static char *
readline(char *prompt)
{
	if (prompt) {
		printf("%s", prompt);
		fflush(stdout);
	}
	return grad_readline_internal(rl_instream);
}
#endif

static int
grad_getc(FILE * stream)
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
grad_readline_init(char *name,
		   int interactive,
		   char **(*completion_fp)(char *cmd, int start, int end))
{
	_interactive = interactive;
	if (!interactive)
		return;
#ifdef WITH_READLINE
	rl_readline_name = name;
	rl_attempted_completion_function = (CPPFunction *) completion_fp;
	rl_getc_function = grad_getc;
#endif
}

void
grad_readline_set_input(FILE *fp)
{
	rl_instream = fp;
}

char *
grad_readline(char *prompt)
{
	if (_interactive)
		return readline(prompt);
	return grad_readline_internal(rl_instream);
}



/* History */

void
grad_add_history (char *line)
{
#ifdef WITH_READLINE
	if (_interactive)
		add_history(line);
#endif
}

#ifdef WITH_READLINE
static char *
get_history_file_name()
{
	static char *filename = NULL;

	if (!filename) {
		char *home = getenv ("HOME");
		if (!home) {
			struct passwd *pw = getpwuid (getuid ());
			if (!pw)
				return NULL;
			home = pw->pw_dir;
		}
		grad_astrcat(&filename, home, "/.", rl_readline_name,
			     "_history", NULL);
	}
	return filename;
}
#endif

int
grad_read_history_file()
{
#ifdef WITH_READLINE
	return _interactive ? read_history(get_history_file_name()) : 0;
#endif
}

int
grad_write_history_file()
{
#ifdef WITH_READLINE
	return _interactive ? write_history(get_history_file_name()) : 0;
#endif
}

