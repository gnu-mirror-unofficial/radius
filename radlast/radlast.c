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
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <netinet/in.h>
#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
#endif

#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <nas.h>
#include <log.h>

#define IP_ADDR_LEN 15

struct user_chain {
	struct user_chain *next;
	char *name;
};

typedef struct wtmp_chain WTMP;
struct wtmp_chain {
	WTMP *next;
	WTMP *prev;
	struct radutmp ut;
};	

void radwtmp();
void adduser(char*);
void usage();
void license();
int want(struct radutmp *);
void add_logout(struct radutmp *bp);
void add_nas_restart(struct radutmp *bp);
WTMP *find_login(struct radutmp *bp);
WTMP *find_logout(struct radutmp *bp);
WTMP *find_restart(struct radutmp *bp);
void print_entry(WTMP *pp, struct radutmp *bp, int mark);
void print_reboot_entry(struct radutmp *bp);
void delete_logout(WTMP *pp, struct radutmp *utp);
WTMP *add_wtmp_entry(WTMP **first, WTMP *pp);
WTMP *delete_wtmp_entry(WTMP **first, WTMP *pp);
WTMP *find_wtmp_nas(WTMP *first, struct radutmp *bp);
WTMP *find_wtmp_nas_port(WTMP *first, struct radutmp *bp);
WTMP *find_wtmp_nas_port_sid(WTMP *first, struct radutmp *bp);

UINT4 host_ip = 0;
UINT4 nas_ip = 0;
int port = 0;
int width = 5;
int sflag = 0;
int mark_missing_stops = 0;
int long_fmt = 0;
int namesize = 10;
int nas_name_len = 8;

int maxrec = -1;
char *file = RADLOG_DIR "/" RADWTMP;
struct radutmp buf[1024];

/* List of users user wants to get info about */
struct user_chain *user_chain, *user_last;
/* True if user wants to see NAS reboot records */
int show_reboot_rec;
/* True if user wants to see NAS shutdown records */
int show_shutdown_rec;

/* List of logouts without logins */
WTMP *logout_list;
/* List of recent logins */
WTMP *login_list;
/* List of NAS up/down transitions */
WTMP *nas_updown_list;

#define OPTSTR "?0123456789c:f:h:mn:lLp:st:w"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {
	"count",              required_argument, 0, 'c',
	"file",               required_argument, 0, 'f',
	"help",               no_argument,       0, '?',
	"host",               required_argument, 0, 'h',
	"license",            no_argument,       0, 'L',
	"missed-stops",       no_argument,       0, 'm',
	"nas",                required_argument, 0, 'n',
	"long-format",        no_argument,       0, 'l',
	"port",               required_argument, 0, 'p',
	"show-seconds",       no_argument,       0, 's',
	"wide",               no_argument,       0, 'w',
	0
};
# define GETOPT getopt_long
#else
# define longopt 0
# define GETOPT(ac,av,os,lo,li) getopt(ac,av,os)
#endif

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	char *p;

	initlog(argv[0]);
	while ((c = GETOPT(argc, argv, OPTSTR, longopt, NULL)) != EOF)
		switch (c) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			if (maxrec == -1) {
				p = argv[optind - 1];
				if (p[0] == '-' && p[1] == c && !p[2])
					maxrec = atol(++p);
				else
					maxrec = atol(argv[optind] + 1);
				if (!maxrec) {
					radlog(L_ERR, "invalid number of records");
					return 1;
				}
			}
			break;
		case 'c':
			maxrec = atol(optarg);
			if (!maxrec) {
				radlog(L_ERR, "invalid number of records");
				return 1;
			}
			break;
		case 'f':
			file = optarg;
			break;
		case 'h':
			host_ip = htonl(get_ipaddr(optarg));
			break;
		case 'L':
			license();
			exit(0);
		case 'm':
			mark_missing_stops++;
			break;
		case 'n':
			nas_ip = get_ipaddr(optarg);
			if (!nas_ip) {
				NAS *nas;
				read_naslist();
				nas = nas_find_by_name(optarg);
				if (nas)
					nas_ip = nas->ipaddr;
				else
					radlog(L_ERR, "unknown nas: %s", optarg);
			}
			nas_ip = htonl(nas_ip);
			break;
		case 'l':
			long_fmt++;
			break;
		case 'p':
			if (*optarg == 's' || *optarg == 'S')
				++optarg;
			port = atoi(optarg);
			break;
		case 's':
			sflag++;	/* Show delta as seconds */
			break;
		case 't':
			if (*optarg == 's' || *optarg == 'S')
				++optarg;
			port = atoi(optarg);
			break;
		case 'w':
			width = 8;
			break;
		case '?':
		default:
			usage();
		}

	if (sflag && width == 8)
		usage();

	if (argc) {
		setlinebuf(stdout);
		for (argv += optind; *argv; ++argv) {
			adduser(*argv);
		}
	}
	radpath_init();
	read_naslist();
	radwtmp();
	return 0;
}

#if 0
int
rawread()
{
	int wfd;
	struct radutmp ut;
	struct tm *tm;
	char ct[256];
	UINT4 ipaddr;
	char ip_str[DOTTED_QUAD_LEN];
	
	if ((wfd = open(file, O_RDONLY, 0)) < 0) {
		radlog(L_ERR, "can't open %s: %s", file, strerror(errno));
		exit(1);
	}
	while (read(wfd, &ut, sizeof ut) == sizeof ut) {
		tm = localtime(&ut.time);
		strftime(ct, sizeof(ct), "%c", tm);

		ipaddr = ut.framed_address;
		ipaddr2str(ip_str, ntohl(ipaddr));
		
		printf("%d %-*.*s %-*.*s %3.3d %-4.4s %c %-*.*s %-*.*s %-*.*s %10.10s %5.5s\n",
		       ut.type,
		       
		       namesize, namesize,
		       ut.login,
		       
		       nas_name_len, nas_name_len,
		       nas_name(ntohl(ut.nas_address)),

		       ut.nas_port,

		       proto_str(ut.proto),

		       ut.porttype,

		       RUT_IDSIZE, RUT_IDSIZE,
		       ut.session_id,

		       RUT_PNSIZE, RUT_PNSIZE,
		       ut.caller_id[0] == 0 ? "?" : ut.caller_id,
		       
		       IP_ADDR_LEN, IP_ADDR_LEN,
		       ip_str,
		       
		       ct, ct + 11);
	}
	close(wfd);
	return;
}
#endif

void
radwtmp()
{
	int wfd;
	struct stat stb;
	int bl;
	struct radutmp *bp;
	int bytes;
	struct tm *tm;
	char ct[256];
	WTMP *pp;
	
	if ((wfd = open(file, O_RDONLY, 0)) < 0 || fstat(wfd, &stb) == -1) {
		radlog(L_ERR, "can't open %s: %s", file, strerror(errno));
		exit(1);
	}
	bl = (stb.st_size + sizeof(buf) - 1) / sizeof(buf);
	
	/*time(&buf[0].ut_time);*/
	
	while (--bl >= 0) {
		if (lseek(wfd, (off_t)(bl * sizeof(buf)), L_SET) == -1 ||
		    (bytes = read(wfd, buf, sizeof(buf))) == -1)
			radlog(L_ERR, "%s", file);
		for (bp = &buf[bytes / sizeof(buf[0]) - 1]; bp >= buf; --bp) {
			switch (bp->type) {
			case P_LOGIN:
				if (pp = find_logout(bp)) {
					if (want(bp)) {
						print_entry(pp, bp, 0);
						if (maxrec != -1 && !--maxrec)
							return;
					}
					delete_logout(pp, bp);
				} else if (pp = find_restart(bp)) {
					if (want(bp)) {
						print_entry(pp, bp, 0);
						if (maxrec != -1 && !--maxrec)
							return;
					}
				} else if (pp = find_login(bp)) {
					/* Ignore duplicate logins */
					if (strncmp(pp->ut.session_id,
						   bp->session_id,
						   RUT_IDSIZE) == 0)
						break; 
					/*
					 * This login misses logout
					 */
					if (want(bp)) {
						print_entry(pp, bp,
							    mark_missing_stops);
						if (maxrec != -1 && !--maxrec)
							return;
					}
					/* Update login information */
					pp->ut = *bp;
				} else {
					if (want(bp)) {
						print_entry(NULL, bp, 0);
						if (maxrec != -1 && !--maxrec)
							return;
					}
				}
				break;
			case P_IDLE:
				/*if (!find_logout_sid(bp))*/
					add_logout(bp);
				break;
			case P_NAS_SHUTDOWN:
			case P_NAS_START:
				add_nas_restart(bp);
				if (want(bp)) {
					print_reboot_entry(bp);
					if (maxrec != -1 && !--maxrec)
						return;
				}
				break;
			default:
				break;
			}
		}
	}
	
	tm = localtime(&buf[0].time);
	(void) strftime(ct, sizeof(ct), "\nradwtmp begins %c\n", tm);
	printf(ct);
}

int
want(ut)
	struct radutmp *ut;
{
	/* First see if it's a reboot/shutdown record and handle it
	 * accordingly
	 */  
	if (ut->type == P_NAS_START) {
		if (show_reboot_rec) 
			return (nas_ip == 0 || ut->nas_address == nas_ip) ;
	} else if (ut->type == P_NAS_SHUTDOWN) {
		if (show_shutdown_rec) 
			return (nas_ip == 0 || ut->nas_address == nas_ip) ;
	} else {
		/* Process ususal login/logout entry */
	
		if (user_chain) {
			struct user_chain *cp;
			
			for (cp = user_chain; cp; cp = cp->next) {
				if (strcmp(cp->name, ut->login) == 0) {
					if (host_ip != 0)
						return ut->framed_address == host_ip ;
					if (nas_ip != 0)
						return ut->nas_address == nas_ip;
					if (port != 0)
						return ut->nas_port == port;
					return 1;
				}
			}
		}
		if (show_reboot_rec || show_shutdown_rec)
			return 0;

		if (host_ip != 0 && ut->framed_address == host_ip) 
			return 1;

		if (nas_ip != 0 && ut->nas_address == nas_ip)
			return 1;
	
		if (port != 0 && ut->nas_port == port)
			return 1;
	}
	return host_ip == 0 && nas_ip == 0 && user_chain == 0 && port == 0;
}

void
adduser(s)
	char *s;
{
	struct user_chain *uc;

	if (*s == '~') {
		if (strcmp(s+1, "reboot") == 0)
			show_reboot_rec = 1;
		else if (strcmp(s+1, "shutdown") == 0)
			show_shutdown_rec = 1;
	}

	uc = emalloc(sizeof(*uc));
	uc->next = NULL;
	if (user_last) 
		user_last->next = uc;
	else
		user_chain = uc;
	uc->name = estrdup(s);
	user_last = uc;
}

/*
 * Add WTMP entry to the head of the list
 */
WTMP *
add_wtmp_entry(first, pp)
	WTMP **first;
	WTMP *pp;
{
	assert(*first!=pp);
	pp->prev = NULL;
	pp->next = *first;
	if (*first)
		(*first)->prev = pp;
	*first = pp;
	return pp;
}

/*
 * Delete WTMP entry from the list.
 * NOTE: Does not free the entry itself
 */
WTMP *
delete_wtmp_entry(first, pp)
	WTMP **first;
	WTMP *pp;
{
	WTMP *p;

	if (pp == *first) 
		*first = (*first)->next;
	if (p = pp->prev) 
		p->next = pp->next;
	if (p = pp->next)
		p->prev = pp->prev;
	return pp;
}

WTMP *
find_wtmp_nas(first, bp)
	WTMP *first;
	struct radutmp *bp;
{
	WTMP *wp;
	
	for (wp = first; wp; wp = wp->next) {
		if (wp->ut.nas_address == bp->nas_address)
			break;
	}
	return wp;
}

WTMP *
find_wtmp_nas_port(first, bp)
	WTMP *first;
	struct radutmp *bp;
{
	WTMP *wp;
	
	for (wp = first; wp; wp = wp->next) {
		if (wp->ut.nas_address == bp->nas_address &&
		    wp->ut.nas_port == bp->nas_port) 
			break;
	}
	return wp;
}

WTMP *
find_wtmp_nas_port_sid(first, bp)
	WTMP *first;
	struct radutmp *bp;
{
	WTMP *wp;
	
	for (wp = first; wp; wp = wp->next) {
		if (wp->ut.nas_address == bp->nas_address &&
		    wp->ut.nas_port == bp->nas_port &&
		    strncmp(wp->ut.session_id, bp->session_id, RUT_IDSIZE)==0) 
			break;
	}
	return wp;
}

/* ************************************************************************* */

void
add_logout(bp)
	struct radutmp *bp;
{
	WTMP *wp;

	wp = emalloc(sizeof(*wp));
	wp->ut = *bp;
	add_wtmp_entry(&logout_list, wp);
	/* purge deleted queue */
	if (wp = find_wtmp_nas_port(login_list, bp)) {
		delete_wtmp_entry(&login_list, wp);
		efree(wp);
	}
}

void
add_nas_restart(bp)
	struct radutmp *bp;
{
	WTMP *wp;

	if (wp = find_wtmp_nas(nas_updown_list, bp)) {
		delete_wtmp_entry(&nas_updown_list, wp);
		efree(wp);
	}
		    
	wp = emalloc(sizeof(*wp));
	wp->ut = *bp;
	add_wtmp_entry(&nas_updown_list, wp);
}

WTMP *
find_login(bp)
	struct radutmp *bp;
{
	return find_wtmp_nas_port(login_list, bp);
}

WTMP *
find_logout_sid(bp)
	struct radutmp *bp;
{
	return find_wtmp_nas_port_sid(logout_list, bp);
}

WTMP *
find_logout(bp)
	struct radutmp *bp;
{
	return find_wtmp_nas_port(logout_list, bp) ;
}

WTMP *
find_restart(bp)
	struct radutmp *bp;
{
	return find_wtmp_nas(nas_updown_list, bp);
}

void
delete_logout(pp, utp)
	WTMP *pp;
	struct radutmp *utp;
{
	static int count;
	
	delete_wtmp_entry(&logout_list, pp);
	pp->ut = *utp;
	count++;
	add_wtmp_entry(&login_list, pp);
}

/* ************************************************************************* */

char *
proto_str(id)
	int id;
{
	if (id == 'S')
		return "SLIP";
	if (id == 'P')
		return "PPP";
	return "shell";
}

/* NOTE:
 *  short format is:
 * LOGIN      NAS     PORT FRAMED-IP       START_TIME - STOP_TIME (DURATION)
 *  long format is:
 * LOGIN      NAS     PORT PROTO PORT_TYPE SESSION_ID  CALLER_ID FRAMED-IP       START_TIME - STOP_TIME (DURATION)
 */
void
print_entry(pp, bp, mark)
	WTMP *pp;
	struct radutmp *bp;
	int mark;
{
	struct tm *tm;
	char ct[256];
	char ip_str[IP_ADDR_LEN+1];
	time_t delta;
	UINT4 ipaddr;
	
	tm = localtime(&bp->time);
	strftime(ct, sizeof(ct), "%c", tm);

	ipaddr = bp->framed_address;
	if (ipaddr == 0 && pp)
		ipaddr = pp->ut.framed_address;
	ipaddr2str(ip_str, ntohl(ipaddr));

	if (long_fmt) {                                   
		printf("%-*.*s %-*.*s %3.3d %-4.4s %c %-*.*s %-*.*s %-*.*s %10.10s %5.5s ",
		       namesize, namesize,
		       bp->login,
		       
		       nas_name_len, nas_name_len,
		       nas_name(ntohl(bp->nas_address)),

		       bp->nas_port,

		       proto_str(bp->proto),

		       bp->porttype,

		       RUT_IDSIZE, RUT_IDSIZE,
		       bp->session_id,

		       RUT_PNSIZE, RUT_PNSIZE,
		       bp->caller_id[0] == 0 ? "?" : bp->caller_id,
		       
		       IP_ADDR_LEN, IP_ADDR_LEN,
		       ip_str,
		       
		       ct, ct + 11);

	} else {
		printf("%-*.*s %-*.*s %3.3d %-*.*s %10.10s %5.5s ",
		       namesize, namesize,
		       bp->login,
		       
		       nas_name_len, nas_name_len,
		       nas_name(ntohl(bp->nas_address)),

		       bp->nas_port,

		       IP_ADDR_LEN, IP_ADDR_LEN,
		       ip_str,
		       
		       ct, ct + 11);
	}
	
	if (pp == NULL) {
		printf("still logged in");
	} else {
		tm = localtime(&pp->ut.time);
		strftime(ct, sizeof(ct), "%c", tm);
		printf("- %5.5s", ct + 11);

		/*delta = pp->ut.duration;*/
		delta = pp->ut.time - bp->time;
		if (sflag) {
			printf("  (%8lu)", delta);
		} else {
			if (delta < 0)
				delta = 0;
			tm = gmtime(&delta);
			strftime(ct, sizeof(ct), "%c", tm);
			if (delta < 86400)
				printf("  (%*.*s)", width, width, ct + 11);
			else
				printf(" (%ld+%*.*s)",
				       delta / 86400, width, width, ct + 11);
		}
	}
	if (mark)
		printf(" !");
	printf("\n");
}

void
print_reboot_entry(bp)
	struct radutmp *bp;
{
	char *s;
	struct tm *tm;
	char ct[256];

	tm = localtime(&bp->time);
	strftime(ct, sizeof(ct), "%c", tm);

	if (bp->type == P_NAS_SHUTDOWN)
		s = "shutdown";
	else
		s = "reboot";
	printf("%-*.*s %s      ~                   %10.10s %5.5s\n",
	       namesize, namesize,
	       s,
		       
	       nas_name(ntohl(bp->nas_address)),
	       ct, ct + 11);
}


char usage_str[] =
#ifdef HAVE_GETOPT_LONG
"usage: radlast [options] [user ...]\n"
"Options are:\n"
"    -c, --count NUMBER          show at most NUMBER records\n"
"    -NUMBER                     the same as above\n"
"    -f, --file FILENAME         use FILENAME as radwtmp\n"
"    -h, --host IPADDR           show logins with IPADDR\n"
"    -m, --missed-stops          mark records with missed stops with bump (!)\n"
"    -n, --nas NAS               show logins from given NAS\n"
"    -l, --long-format           use long output format\n"
"    -L, --license               display license and exit\n"
"    -p, --port PORT             show logins from given PORT\n"
"    -s, --show-seconds          show the login session duration in seconds\n"
"    -w, --wide                  widen the duration field to show seconds\n"
"    -?, --help                  show this help info"
#else
"usage: radlast [options] [user ...]\n"
"Options are:\n"
"    -c NUMBER                   show at most NUMBER records\n"
"    -NUMBER                     the same as above\n"
"    -f FILENAME                 use FILENAME as radwtmp\n"
"    -h IPADDR                   show logins with IPADDR\n"
"    -m                          mark records with missed stops with bump (!)\n"
"    -n NAS                      show logins from given NAS\n"
"    -l                          use long output format\n"
"    -L                          display license and exit\n"
"    -p PORT                     show logins from given PORT\n"
"    -s                          show the login session duration in seconds\n"
"    -w                          widen the duration field to show seconds\n"
"    -?                          show this help info"
#endif
;

void
usage(void)
{
	fprintf(stderr,
		"%s\n",
		usage_str);
	exit(1);
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





