/* This file is part of GNU RADIUS.
 * Copyright (C) 2001, Sergey Poznyakoff
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
/*
 * This program is a part of test suite. It determines first N available
 * UDP ports to be used.
 * usage: findport [-c N][-s P][-m P][-f F]
 * Options are:
 *         -c N        Find first N not-used ports (default 1)
 *         -s P        Start from port P+1 (default 1024)
 *         -m P        Finish when port P is reached (default 65535)
 *         -f F        Use format string F for output.
 * Any subsequent occurence of characters %d in format string is replaced
 * with the found port number. Usual C backslash sequences are recognized.
 * All other characters encountered in format string are reproduced
 * verbatim.
 * If no format string is specified, the port numbers are printed one per
 * line of output.
 * Return value: 0 if OK, 1 on error.
 * Bugs: No check is made to ensure that the number of %d markers in format
 *       string coincides with number N. 
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

void output(int);
char *format = NULL;

main(argc, argv)
	int argc;
	char **argv;
{
	char *progname = argv[0]; 
	int local_port, max_port, num_ports;
	struct	sockaddr	salocal;
	struct	sockaddr_in	*sin;
	int fd;
	
	/* Process command line */
	local_port = 1024;
	max_port = 65535;
	num_ports = 1;

	#define OPTARG (*argv)[2] ? *argv+2 : *++argv
	while (*++argv) {
		if (**argv == '-') {
			switch ((*argv)[1]) {
			case 's':
				local_port = atoi(OPTARG);
				break;
			case 'm':
				max_port = atoi(OPTARG);
				break;
			case 'c':
				num_ports = atoi(OPTARG);
				break;
			case 'f':
				format = OPTARG;
				break;
			default:
				fprintf(stderr,
					"%s: unknown switch: %s\n",
					progname, *argv);
				return 1;
			}
		} else {
			fprintf(stderr,
				"%s: stray argument %s\n", progname, *argv);
			return 1;
		}
	}
	
	while (num_ports--) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			fprintf(stderr,
				"%s: can't open socket: %s\n",
				progname, strerror(errno));
			return 1;
		}

		sin = (struct sockaddr_in *) &salocal;
		memset(sin, 0, sizeof (salocal));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = INADDR_ANY;

		do {
			if (++local_port > max_port) {
				fprintf(stderr, "%s: can't bind socket\n",
					progname);
				return 1;
			}
			sin->sin_port = htons((u_short)local_port);
		} while ((bind(fd, &salocal, sizeof(struct sockaddr_in)) < 0) &&
			 local_port < max_port);
		output(local_port);
		close(fd);
	}
	output(0);
	return 0;
}

void
output(port)
	int port;
{
	if (!format) {
		if (port)
			printf("%d\n", port);
		return;
	}
	
	while (*format) {
		if (port && format[0] == '%' && format[1] == 'd') {
			printf("%d", port);
			format += 2;
			break;
		} else if (format[0] == '\\' && format[1]) {
			switch (format[1]) {
			case 'a':
				putchar('\a');
				break;
			case 'b':
				putchar('\b');
				break;
			case 'n':
				putchar('\n');
				break;
			case 't':
				putchar('\t');
				break;
			case 'v':
				putchar('\v');
				break;
			case '\\':
				putchar('\\');
				break;
			default:
				putchar(format[0]);
				putchar(format[2]);
				break;
			}
			format += 2;
		} else
			putchar(*format++);
	}
}
