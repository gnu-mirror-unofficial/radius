/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <radlib.h>

static int
get_argcv(const char *str, const char *delim, size_t *pargc, char ***pargv)
{
	int n;
	int argc;
	char **argv;

	if (n = grad_argcv_get(str, delim, "#", &argc, &argv)) {
		grad_argcv_free(argc, argv);
		return n;
	}
	
	*pargc = argc;
	*pargv = argv;
	return 0;
}

static int
continuation_line_p(const char *str, const char *delim)
{
	int argc;
	char **argv;
	int rc = get_argcv(str, delim, &argc, &argv) == 0
		&& argc > 0
		&& argv[argc-1][strlen(argv[argc-1]) - 1] == '\\';
	grad_argcv_free(argc, argv);
	return rc;
}

int
grad_read_raddb_file(char *filename, int vital, char *delim,
		     int (*fun)(), void *closure)
{
        int    argc;
        char **argv;
        grad_locus_t loc;
	int fd;
	struct stat st;
	char *buffer, *lineptr, *endp, *p;
	size_t rdsize;
	
	if (stat(filename, &st)) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't stat `%s'"), filename);
                return -1;
        }
	fd = open(filename, O_RDONLY);
        if (fd == -1) {
                if (vital) {
                        grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                                 _("can't open file `%s'"),
                                 filename);
                        return -1;
                } else {
                        grad_log(GRAD_LOG_NOTICE|GRAD_LOG_PERROR, 
                                 _("can't open file `%s'"),
                                 filename);
                        return 0;
                }
        }
	
	buffer = grad_malloc(st.st_size + 1);
	for (lineptr = buffer, rdsize = st.st_size; rdsize; ) {
		ssize_t s = read(fd, lineptr, rdsize);
		if (s <= 0) {
			if (s == -1) {
				grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
				         _("%s: read error"),
					 filename);
			} else if (s == 0) 
				grad_log(GRAD_LOG_WARN, _("%s: short read"),
					  filename);
			grad_free(buffer);
			close(fd);
			return 1;
		}
		rdsize -= s;
		lineptr += s;
	}
	*lineptr = 0;
	close(fd);
	
	if (!delim)
		delim = "";
	loc.file = filename;
        loc.line = 0;
	lineptr = buffer;

	for (p = endp = lineptr; *endp;) {
		if (endp[0] == '\\' && endp[1] == '\n') {
			endp[1] = 0;
			if (continuation_line_p(lineptr, delim)) {
				endp += 2;
				lineptr = endp;
				continue;
			} else 
				endp[1] = '\n';
		} else if (endp[0] == '\n')
			lineptr = endp;
		*p++ = *endp++;
	}
	*p = 0;
	
	lineptr = buffer;
	while (*lineptr) {
		char *str;
		
		for (endp = lineptr; *endp && *endp != '\n'; endp++) 
			;
		
		if (*endp)
			*endp++ = 0;
		loc.line++;
		str = lineptr;
		lineptr = endp;
		if (str[0] == 0)
			continue;
		
                if (get_argcv(str, delim, &argc, &argv) == 0 && argc)
			fun(closure, argc, argv, &loc);

                if (argv)
                        grad_argcv_free(argc, argv);
        }

	grad_free(buffer);

        return 0;
}
