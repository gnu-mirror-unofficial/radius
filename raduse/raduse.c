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

static char rcsid[] = 
"$Id$";

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/in.h>
#if defined(sun)
# include <fcntl.h>
#endif
#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <radlast.h>
#include <log.h>
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif
#include "display.h"
#include "screen.h"

#define MAX_PORTS 256

#define C_B 2
#define C_F 6

typedef struct nasstat {
	struct nasstat *next;
	UINT4			ipaddr;
	int                     use;
	char			longname[256];
	char			shortname[32];
	char			nastype[32];
	int                     nports;
	PORT_STAT               *port;
} NASSTAT;

/* various options */
int width = 5;            /* width for time output (5 - hh:mm, 8 - hh:mm:ss) */
int delay = 1;            /* delay between screen updates (seconds) */
int maxscreens = -1;      /* max. number of screens to display */
int numscreens = 0;       /* number of screens displayed so far */
int brief = 0;            /* brief mode (don't show inuse/idle statistics) */
int show_idle = 1;        /* show idle lines */
int interactive = -1;     /* interactive mode */
int dump_only = 0;

char *file;
NASSTAT *naslist;
int nas_cnt;

time_t starttime;
unsigned offset;


void raduse();
int collect(int);
int update(int);
PORT_STAT * find_port(NASSTAT *nas, int port_no);
void listnas();
void usage();
void license();
NASSTAT *nasstat_find(UINT4);
NASSTAT *nasstat_find_by_name(char *);
void add_login(NASSTAT *nas, struct radutmp *bp);
void add_logout(NASSTAT *nas, WTMP *pp, struct radutmp *bp);
char * nasstat_name(UINT4 ipaddr);
void add_nas(char*);
void use_all();
void display();
int read_naslist();
void raduse();
void mark_all(int);
int mark_nas(char *);
void select_nas();
void dump(int);

#define OPTSTR "bd:DhIilLns:wx"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {
	"brief",         no_argument,       0, 'b',
        "display",       required_argument, 0, 'd',
	"dump",          no_argument,       0, 'D',
	"no-idle-lines", no_argument,       0, 'I',
	"interactive",   no_argument,       0, 'i',
	"no-interactive",no_argument,       0, 'n',
	"delay",         required_argument, 0, 's',
	"widen",         no_argument,       0, 'w',
	"license",       no_argument,       0, 'L',
	"list-nas",      no_argument,       0, 'l',
	"help",          no_argument,       0, 'h',
	0,
};
#else
# define longopt 0
# define getopt_long(ac,av,os,lo,li) getopt(ac,av,os)
#endif

/*
 * Debugging hook.
 * To debug, define symbol DEBUG, run raduse as
 *     raduse -x
 * and connect to it with gdb from another terminal.
 */
#if defined DEBUG
volatile int stop = 1;

void
wait_debug()
{
	printf("READY TO DEBUG: %d\n", getpid());
	while (!stop)
		;
}
#else
# define wait_debug()
#endif


int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;

	app_setup();	
	initlog(argv[0]);
	read_naslist();
	while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF)
		switch(c) {
		case 'b':
			brief = !brief;
			break;
		case 'd':
			maxscreens = atoi(optarg);
			break;
		case 'D':
			dump_only++;
			break;
		case 'h':
			usage();
			/*NOTREACHED*/
		case 'I':
			show_idle = !show_idle;
			break;
		case 'i':
			interactive = 1;
			break;
		case 'L':
			license();
			return 0;
		case 'l':
			listnas();
			return 0;
		case 'n':
			interactive = 0;
			break;
		case 's':
			delay = atoi(optarg);
			break;
		case 'w':
			width = 8;
			break;
#ifdef DEBUG
		case 'x':
			stop = 0;
			break;
#endif			
		default:
			break;
		}

	radpath_init();
	file = radstat_path;

	if (optind == argc) {
		mark_all(1);
	} else {
		for (argv += optind; *argv; ++argv) 
			add_nas(*argv);
	}

	setlinebuf(stdout);
	
	setvbuf(stdout, NULL, _IONBF, 0);

	wait_debug();
	
	init_termcap(interactive);
	if (interactive == -1)
		interactive = smart_terminal;
	
	alloc_screen(nas_cnt, MAX_PORTS);
	init_screen();
	raduse();
	restore_screen();
	return 0;	
}

int
stat_insert_port(port)
	PORT_STAT *port;
{
	NASSTAT *nas = nasstat_find(port->ip);

	if (!nas) {
		char ipbuf[DOTTED_QUAD_LEN];
		
		radlog(L_ERR,
		    _("stat_insert_port(): portno %d: can't find nas for IP %s"),
		    port->port_no,
		    ipaddr2str(ipbuf, port->ip));
		free_entry(port);
		return -1;
	}

	if (nas->port == NULL) {
		nas->port = port;
	} else if (nas->port->port_no > port->port_no) {
		port->next = nas->port;
		nas->port = port;
	} else {
		PORT_STAT *p, *prevp = NULL;

		for (p = nas->port; p; prevp = p, p = p->next) {
			if (p->port_no > port->port_no)
				break;
		}
		port->next = p;
		prevp->next = port;
	}
	nas->nports++;
	return 0;
}


int
collect(fd)
	int fd;
{
	PORT_STAT stat;
	PORT_STAT *port;
	NASSTAT *nas;
	char ipbuf[DOTTED_QUAD_LEN];
	
	if (lseek(fd, sizeof(PORT_STAT), SEEK_SET) != sizeof(PORT_STAT)) {
		radlog(L_ERR, _("lseek error on `%s' (%d): %s"),
		    file, sizeof(PORT_STAT), strerror(errno));
		return 1;
	}
	while (read(fd, &stat, sizeof(stat)) == sizeof(stat)) {
		if (stat.ip == 0)
			break;

		nas = nasstat_find(stat.ip);
		if (!nas) {
			radlog(L_ERR,
			    _("collect(): port %d: can't find nas for IP %s"),
			    stat.port_no,
			    ipaddr2str(ipbuf, stat.ip));
			return 1;
		}

		port = find_port(nas, stat.port_no);
		if (!port) {
			port = alloc_entry(sizeof(*port));
			stat.next = 0;
			*port = stat;
			stat_insert_port(port);
		} else {
			port->active = stat.active;               
			strncmp(port->login, stat.login, sizeof(port->login));
			port->count = stat.count;                
			port->start = stat.start;
			port->lastin = stat.lastin;            
			port->lastout = stat.lastout;           
			port->inuse = stat.inuse;             
			port->idle = stat.idle;              
			port->maxinuse = stat.maxinuse;
			port->maxidle = stat.maxidle;
		}
	}
	return 0;
}

PORT_STAT *
find_port(nas, port_no)
	NASSTAT *nas;
	int port_no;
{
	PORT_STAT *port;
	
	/* First try to find it in the cached buffer */
	for (port = nas->port; port; port = port->next) 
		if (port->port_no == port_no)
			return port;
	return NULL;
}

void
raduse()
{
	int wfd;
	struct stat stb;
	PORT_STAT stat;
	struct timeval timeout;
	fd_set rfd;
	char cmd;
	time_t lastmtime;
	
	wfd = open(file, O_RDONLY);
	if (wfd == -1) {
		radlog(L_ERR|L_PERROR, _("can't open `%s'"), file);
		return;
	}
	
	/* Read header record */
	if (read(wfd, &stat, sizeof(stat)) != sizeof(stat)) {
		radlog(L_ERR, _("read error on `%s': %s"),
		    file, strerror(errno));
		return;
	}
	starttime = stat.start;
	fstat(wfd, &stb);
	lastmtime = stb.st_mtime;
	offset = sizeof(stat);
	
	if (dump_only) {
		dump(wfd);
		return;
	}
	
	if (collect(wfd))
		return;
	
	while (maxscreens == -1 || (numscreens++ < maxscreens)) {
		display();

		FD_ZERO(&rfd);
		FD_SET(1, &rfd);
		timeout.tv_sec = delay;
		timeout.tv_usec = 0;

/*		fstat(wfd, &stb);
		if (stb.st_mtime > lastmtime) {
			collect(wfd);
		}
*/
		collect(wfd);
		
		if (interactive &&
		    select(32, &rfd, NULL, NULL, &timeout) > 0) {
			read(0, &cmd, 1);
			switch (cmd) {
			case '\n':
			case ' ':
				/* refresh */
				clearmsg();
				break;
			case '\f':
				clear();
				display();
				break;
			case '^':
				firstpage();
				break;
			case 'b':
				brief = !brief;
				if (brief)
					clear();
				break;
			case C_B:
				page(-1);
				break;
			case C_F:
				page(1);
				break;
			case 'i':
				show_idle = !show_idle;
				if (!show_idle)
					clear();
				break;
			case 'j': /* Next record */
				/*scroll(brief ? 1 : 3);*/
				scroll(1);
				break;
			case 'G':
			case '$':
				lastpage();
				break;
			case 'k': /* Prev record */
				/*scroll(brief ? -1 : -3);*/
				scroll(-1);
				break;
			case 'q': /* ie. stop */
				numscreens = maxscreens = 0; 
				break;
			case 's':
				getint(_("Seconds to delay: "), &delay);
				break;
			case 't':
				select_nas();
				break;
			default:
				msg(MT_standout,
				    _("unknown command: %c"), cmd);
			}
		}
	}
	close(wfd);
}

int
formatdelta(outbuf, delta)
	char *outbuf;
	time_t delta;
{
	char ct[128];
	char buf[128];
	struct tm *tm;

	tm = gmtime(&delta);
	strftime(ct, sizeof(ct), "%c", tm);
	if (delta < 86400)
		sprintf(buf, "%*.*s", width, width, ct + 11);
	else
		sprintf(buf, "%ld+%*.*s",
			delta / 86400, width, width, ct + 11);
	return sprintf(outbuf, "%11.11s ", buf);
}

int
formattime(buf, time)
	char *buf;
	time_t time;
{
	struct tm *tm;
	char ct[128];
	
	tm = localtime(&time);
	strftime(ct, sizeof(ct), "%c", tm);
	return sprintf(buf, "%10.10s %5.5s ", ct, ct + 11);

	/*"%m/%d/%y %H:%M:%S", tm);
	printf("%8.8s %5.5s ", buf, buf + 9);*/
}

int
formatstop(buf, time)
	char *buf;
	time_t time;
{
	struct tm *tm;
	char ct[128];
	
	tm = localtime(&time);
	strftime(ct, sizeof(ct), "%H:%M:%S", tm);
	return sprintf(buf, "%5.5s ", ct);
}
	
void
display()
{
	NASSTAT *nas;
	PORT_STAT *port;
	int j, off = 0;
	time_t now = time(NULL), delta, stop;
	char *str;
	int total_lines = 0, active_lines = 0;
	
	for (nas = naslist; nas; nas = nas->next) {
		for (port = nas->port; port; port = port->next) {
			total_lines++;
			if (port->active)
				active_lines++;
		}
	}

	
	str = headerbuf[0];
	str += sprintf(str, _("uptime "));
	str += formatdelta(str, now - starttime);
	str += sprintf(str, "        ");
	formattime(str, now);
	
	str = headerbuf[1];
	str += sprintf(str, _("%3d lines, %3d active, %3d idle. "),
		       total_lines,
		       active_lines,
		       total_lines - active_lines);
	if (total_lines)
		str += sprintf(str, _("Pool load %4.2f"),
			       (double) active_lines / total_lines);
	else
		str += sprintf(str, _("Pool load ??.??"));

	off = 0;
	for (nas = naslist; nas; nas = nas->next) {
		if (!nas->use)
			continue;
		j = 0;
		for (port = nas->port; port; port = port->next) {
			if (!show_idle && !port->active) 
				continue;
			/* Port number */
			str = screen[off + j++];
			str += sprintf(str, "%-12.12s %3.3d %5d ",
				      nas->shortname,
				      port->port_no, port->count);
			if (port->active) {
				delta = now - port->lastin;
				str += sprintf(str,
					       "%-16.16s ", port->login);
				str += formatdelta(str, delta);
				str += formattime(str, port->lastin);
			} else {
				/* currently idle */
				delta = now - port->lastout;
				str += sprintf(str,
					       "%-16.16s ", "[idle]");
				str += formatdelta(str, delta);
				str += formattime(str, port->lastout);
			}

			if (brief)
				continue;
			str = screen[off + j++];
			str += sprintf(str, "          ");
			/* In use statistics */
			str += formatdelta(str, port->inuse);
			str += formatdelta(str, port->maxinuse.time);
			str += formattime(str, port->maxinuse.start);
			str += sprintf(str, "- ");
			stop = port->maxinuse.start +
				port->maxinuse.time;
			str += formatstop(str, stop);

			/* Port number */
			str = screen[off + j++];
			str += sprintf(str, "          ");

			/* Idle time statistics */
			str += formatdelta(str, port->idle);
			str += formatdelta(str, port->maxidle.time);
			str += formattime(str, port->maxidle.start);
			str += sprintf(str, "- ");
			stop = port->maxidle.start +
				port->maxidle.time;
			str += formatstop(str, stop);
		}
		off += j;
	}
	update_display(off);
}

void
add_nas(name)
	char *name;
{
	NASSTAT *nas;
	
	nas = nasstat_find_by_name(name);
	if (!nas) {
		radlog(L_ERR, _("no such NAS: %s (use raduse -l to get the list)"),
			name);
		exit(1);
	} else
		nas->use++;
}

void
listnas()
{
	NASSTAT *p;
	char ipaddr[16];
	
	for (p = naslist; p; p = p->next) {
		printf("%-32.32s %-10.10s %-16.16s\n",
		       p->longname,
		       p->shortname,
		       ipaddr2str(ipaddr, p->ipaddr));
	}
}

int
read_naslist()
{
	FILE	*fp;
	char	buffer[256];
	char	hostnm[128];
	char	shortnm[32];
	char	nastype[32];
	char    file[256];
	int	lineno = 0;
	NASSTAT	*c;

	if (naslist)
		return 1;
	
	sprintf(file, "%s/%s", RADIUS_DIR, RADIUS_NASLIST);
	if ((fp = fopen(file, "r")) == NULL) {
		radlog(L_CONS|L_ERR, _("can't open %s"), file);
		return -1;
	}
	while (fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		nastype[0] = 0;
		if (sscanf(buffer, "%s%s%s", hostnm, shortnm, nastype) < 2) {
			radlog(L_ERR, _("%s:%d: syntax error"), file, lineno);
			continue;
		}
		c = emalloc(sizeof(*c));
		
		bzero(c, sizeof(*c));
		c->ipaddr = get_ipaddr(hostnm);
		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));
		c->next = naslist;
		naslist = c;
		nas_cnt++;
	}
	fclose(fp);

	return 0;
}

NASSTAT *
nasstat_find(ipaddr)
	UINT4 ipaddr;
{
	NASSTAT *cl;

	for (cl = naslist; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}

NASSTAT *
nasstat_find_by_name(name)
	char *name;
{
	NASSTAT *cl;

	for (cl = naslist; cl; cl = cl->next)
		if (strcasecmp(name, cl->shortname) == 0)
			break;

	return cl;
}

char *
nasstat_name(ipaddr)
	UINT4 ipaddr;
{
	NASSTAT *cl;

	if ((cl = nasstat_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}
	return ip_hostname(ipaddr);
}

void
mark_all(m)
	int m;
{
	NASSTAT *nas;

	for (nas = naslist; nas; nas = nas->next)
		nas->use = m;
}

int
mark_nas(name)
	char *name;
{
	NASSTAT *nas;

	for (nas = naslist; nas; nas = nas->next)
		if (strcasecmp(nas->shortname, name) == 0) {
			nas->use = 1;
			return 0;
		}
	return 1;
}
	
void
select_nas()
{
	char buf[80];
	int n, nas_cnt = 0;
	char *p, *nasname;

#define PROMPT _("NASes to show:")       
	msg(MT_standout, PROMPT);

	if ((n = readline(buf, sizeof(buf)-sizeof(PROMPT), 0)) > 0) {
		mark_all(0);
		p = buf;
		do {
			while (*p && isspace(*p))
				p++;
			if (!*p)
				break;
			nasname = p;
 
			while (*p && !isspace(*p))
				p++;
			if (*p)
				*p++ = 0;
			nas_cnt++;
			if (strcasecmp(nasname, "all") == 0) {
				mark_all(1);
				break;
			} else if (mark_nas(nasname)) {
				msg(MT_standout, _("No such NAS: ``%s'"), nasname);
				mark_all(1);
				return;
			}
		} while (*p);
	}
	if (!nas_cnt) 
		mark_all(1);
	clearmsg();
}

void
dump(fd)
	int fd;
{
	PORT_STAT stat;
	NASSTAT *nas;
	unsigned off = 0;
	
	while (read(fd, &stat, sizeof(stat)) == sizeof(stat)) {
		if (stat.ip != 0) {
			nas = nasstat_find(stat.ip);
			printf("%8d %16.16s %4d\n",
			       off,
			       nas->shortname,
			       stat.port_no);
		}
		off += sizeof(stat);
	}
	return;
}




char usage_str[] = 
#ifdef HAVE_GETOPT_LONG
"usage: raduse [options] [nas [nas...]]\n"
"The options are:\n"
"       -b, --brief               Brief mode.\n"
"       -d, --display COUNT       Show only COUNT displays.\n"
"	-D, --dump                Dump the statistics database to stdout\n"
"                                 and exit.\n"
"	-I, --no-idle-lines       Do not display idle lines.\n"
"	-i, --interactive         Interactive mode.\n"
"	-n, --no-interactive      Non-interactive mode.\n"
"	-s, --delay NUM           Specify delay in seconds between\n"
"                                 screen updates.\n"
"	-w, --widen               Widen the time display fields to show\n"
"                                 the seconds.\n"
"	-l, --list-nas            List the names and IP numbers of\n"
"                                 network access servers and then exit.\n"
"       -L, --license             Display GNU lisense and exit\n"
"	-h, --help                Display short usage summary.\n";
#else
"usage: raduse [options] [nas [nas...]]\n"
"The options are:\n"
"       -b          Brief mode.\n"
"       -d COUNT    Show only COUNT displays.\n"
"       -D          Dump the statistics database to stdout and exit.\n"
"       -I          Do not display idle lines.\n"
"       -i          Interactive mode.\n"
"       -n          Non-interactive mode.\n"
"       -s NUM      Specify delay in seconds between screen updates.\n"
"       -w          Widen the time display fields to show the seconds.\n"
"       -l          List the names and IP numbers of NASes and exit\n"
"       -L          Display GNU license and exit\n"
"       -h          Display short usage summary.\n";
#endif

void 
usage()
{
	printf("%s", usage_str);
	exit(1);
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
license()
{
	printf("%s: Copyright 1999,2000 Sergey Poznyakoff\n", progname);
	printf("\nThis program is part of GNU Radius\n");
	printf("%s", license_text);
	exit(0);
}
