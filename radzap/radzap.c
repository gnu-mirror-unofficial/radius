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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif

#include <radiusd.h>
#include <radutmp.h>

NAS *naslist;
#define LOCK_LEN sizeof(struct radutmp)

static int write_wtmp(struct radutmp *ut, int status);
int radzap(UINT4 nasaddr, int port, char *user, time_t t);
int radzap_wtmp(UINT4 nasaddr, int port, char *user, time_t t);
static int confirm(struct radutmp *ut);
int find_logout(int fd, struct radutmp *utp);
UINT4 findnas(char *nasname);

int confirm_flag;
void usage();
void license();

#define OPTSTR "cd:hl:Ln:p:qw"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {       
	"confirm",             no_argument, 0, 'c',
	"directory",     required_argument, 0, 'd',
	"help",                no_argument, 0, 'h',
	"license",             no_argument, 0, 'L',
	"log-directory", required_argument, 0, 'l',
	"nas",           required_argument, 0, 'n',
	"port",          required_argument, 0, 'p',
	"quiet",               no_argument, 0, 'q',
	0
};
#else
# define longopt 0
# define getopt_long(ac,av,os,lo,li) getopt(ac,av,os)
#endif

/*
 *	Zap a user from the radutmp and radwtmp file.
 */
int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	int	nas_port = -1;
	char	*user = NULL;
	char 	*nas = NULL;
	UINT4	ip = 0;
	time_t	t;
	char	buf[256];
	char *s;	
	int force_wtmp = 0;

	app_setup();
	initlog(argv[0]);

	if (s = getenv("RADZAP_CONFIRM"))
		confirm_flag = atoi(s);
	while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF) {
		switch (c) {
		case 'c':
			confirm_flag = 1;
			break;
		case 'd':
			radius_dir = optarg;
			break;
		case 'l':
			radlog_dir = optarg;
			break;
       		case 'n':
			nas = optarg;
			break;
		case 'p':
			if (*optarg == 's' || *optarg == 'S')
				++optarg;
			nas_port = atoi(optarg);
			break;
		case 'q':
			confirm_flag = 0;
			break;
		case 'h':
			usage();
			return 0;
		case 'L':
			license();
			return 0;
		case 'w':
			force_wtmp ++;
			break;
		default :
			usage();
			return 0;
		}
	}

	radpath_init();
	
	if (argc > optind)
		user = argv[optind];
	/* check the validity of the invocation */
	if (!user && !nas && nas_port == -1) {
		usage();
		return 1;
	}

	/*
	 *	Read the "naslist" file.
	 */
	sprintf(buf, "%s/%s", RADIUS_DIR, RADIUS_NASLIST);
	if (read_naslist_file(buf) < 0)
		exit(1);

	if (nas) {
		/*
		 *	Find the IP address of the terminal server.
		 */
		if ((ip = findnas(nas)) == 0) {
			if ((ip = get_ipaddr(nas)) == 0) {
				fprintf(stderr, "%s: host not found.\n", nas);
				return 1;
			}
		}
	}
		
	t = time(NULL);
	radzap(ip, nas_port, user, t);
	if (force_wtmp)
		radzap_wtmp(ip, nas_port, user, t);
	return 0;
}

/*
 *	Zap a user, or all users on a NAS, from the radutmp file.
 */
int
radzap(nasaddr, port, user, t)
	UINT4 nasaddr;
	int port;
	char *user;
	time_t t;
{
	struct radutmp	u;
	int		fd;
	UINT4		netaddr;

	if (t == 0) 
		time(&t);

	netaddr = htonl(nasaddr);

	if ((fd = open(radutmp_path, O_RDWR|O_CREAT, 0644)) < 0) {
		radlog(L_ERR|L_PERROR, "can't open %s", radutmp_path);
		exit(1);
	}	
	/*
	 *	Find the entry for this NAS / portno combination.
	 */
	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if ((nasaddr != 0 && netaddr != u.nas_address) ||
		      (port >= 0   && port    != u.nas_port) ||
		      (user != NULL && strcmp(u.login, user))!= 0 ||
		       u.type != P_LOGIN) {
			continue;
		}
		if (!confirm(&u))
			continue;
		/*
		 *	Match. Zap it.
		 */
		if (lseek(fd, -(int)sizeof(u), SEEK_CUR) < 0) {
			fprintf(stderr,
				_("radzap: can't lseek -%d bytes\n"),
				sizeof(u));
			exit(1);
		}
		rad_lock(fd, LOCK_LEN, 0, SEEK_CUR);
		u.type = P_IDLE;
		u.time = t;
		write(fd, &u, sizeof(u));
		rad_unlock(fd, LOCK_LEN, -(off_t)sizeof(u), SEEK_CUR);


		u.type = P_IDLE;
		/*
		 *	Add a logout entry to the wtmp file.
		 */
		write_wtmp(&u, DV_ACCT_STATUS_TYPE_STOP);
	}
	close(fd);

	return 0;
}

/* find a logout record for given radutmp entry
 * When called, the file pointer should point right past the utp.  
 * On exit returns 1 if a logout record was found.
 * If logout is not found, returns 0 and leaves file pointer at end-of-file
 */
int
find_logout(fd, utp)
	int fd;
	struct radutmp *utp;
{
	struct radutmp	u;
	int count = 0;

	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if (utp->nas_address == u.nas_address &&
		    utp->nas_port == u.nas_port &&
		    strncmp(utp->login, u.login, sizeof(u.login)) == 0) {
			if (u.type == P_LOGIN) 
				count++;
		    	else if (u.type == P_IDLE && count-- <= 0) 
				return 1;
		}
	}
	return 0;
}

/*
 *	Zap a user, or all users on a NAS, from the radwtmp file.
 */
int
radzap_wtmp(nasaddr, port, user, t)
	UINT4 nasaddr;
	int port;
	char *user;
	time_t t;
{
	struct radutmp	u;
	int		fd;
	UINT4		netaddr;
	long            here;
	
	if (t == 0) 
		time(&t);

	netaddr = htonl(nasaddr);

	if ((fd = open(radwtmp_path, O_RDWR|O_CREAT, 0644)) >= 0) {
	 	/*
		 *	Find the entry for this NAS / portno combination.
		 */
		while (read(fd, &u, sizeof(u)) == sizeof(u)) {

			if ((nasaddr != 0 && netaddr != u.nas_address) ||
			      (port >= 0   && port    != u.nas_port) ||
		   	      (user != NULL && strcmp(u.login, user))!= 0 ||
			       u.type != P_LOGIN) {
				continue;
			}

			here = lseek(fd, 0, SEEK_CUR);
			
			if (!find_logout(fd, &u) && confirm(&u)) {
				/*  Match. Zap it.
				 * Note that find_logout leaves fd at eof.   
				 */

				rad_lock(fd, LOCK_LEN, 0, SEEK_CUR);
				u.type = P_IDLE;
				u.time = t;
				write(fd, &u, sizeof(u));
				rad_unlock(fd, LOCK_LEN, -(off_t)sizeof(u), SEEK_CUR);
			}
			if (lseek(fd, here, SEEK_SET) < 0) {
				fprintf(stderr,
					_("radzap: can't return to position %ld\n"),
					here);
				exit(1);
			}
				
		}
		close(fd);
	}
	return 0;
}


/*
 *	Read the nas file.
 *	FIXME: duplicated from files.c
 */
int
read_naslist_file(file)
	char *file;
{
	FILE	*fp;
	char	buffer[256];
	char	hostnm[128];
	char	shortnm[32];
	char	nastype[32];
	int	lineno = 0;
	NAS	*c;

	if ((fp = fopen(file, "r")) == NULL) {
		perror(file);
		return -1;
	}
	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		nastype[0] = 0;
		if (sscanf(buffer, "%s%s%s", hostnm, shortnm, nastype) < 2) {
			fprintf(stderr, _("%s:%d: syntax error\n"), file, lineno);
			continue;
		}
		c = Alloc_entry(NAS);

		c->ipaddr = get_ipaddr(hostnm);
		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));

		c->next = naslist;
		naslist = c;
	}
	fclose(fp);

	return 0;
}


UINT4
findnas(nasname)
	char *nasname;
{
	NAS *cl;

	for(cl = naslist; cl; cl = cl->next) {
		if (strcmp(nasname, cl->shortname) == 0 ||
		    strcmp(nasname, cl->longname) == 0)
			return cl->ipaddr;
	}

	return 0;
}

	


int
confirm(utp)
	struct radutmp *utp;
{
	char buf[10];
	NAS *cl;
	char *s;
	
	if (cl = nas_find(ntohl(utp->nas_address)))
		s = cl->shortname;
	if (s == NULL || s[0] == 0) 
		s = ip_hostname(ntohl(utp->nas_address));
	
	printf(_("radzap: zapping %s from %s, port %d"),
	       utp->login,
	       s,
	       utp->nas_port);
	if (confirm_flag) {
		printf(": Ok?");
		fgets(buf, sizeof(buf), stdin);
		if (buf[0] != 'y' && buf[0] != 'Y') {
			printf(_("Not confirmed\n"));
			return 0;
		} else
			return 1;
	} 
	printf("\n");
	return 1;
}

int
write_wtmp(ut, status)
	struct radutmp *ut;
	int status;
{
	FILE *fp;
		
	fp = fopen(radwtmp_path, "a");
	if (fp == NULL)
		return -1;
	fwrite(ut, sizeof(*ut), 1, fp);
	fclose(fp);
	return 0;
}


/*
 *	Find a nas in the NAS list.
 */
NAS *
nas_find(ipaddr)
	UINT4 ipaddr;
{
	NAS *cl;

	for(cl = naslist; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}

char usage_text[] =
#ifdef HAVE_GETOPT_LONG
"usage: radzap [-c][-q][-d raddb][-L][-l log_dir] [-n nas][-p port] [user]\n"
"either nas or port or user must be specified\n"
"\n"
"Options are:\n"
"       -c, --confirm            Ask for confirmation before zapping.\n"
"       -d, --directory DIR      Specify Radius configuration directory.\n"
"       -L, --license            Display GNU license and exit.\n"
"       -l, --log-directory DIR  Specify logging directory.\n"
"       -n, --nas NASNAME        NAS from which to zap the user.\n"
"       -p, --port PORT          Port to zap from.\n"
"       -q, --quiet              Do not ask for confirmation before zapping.\n"
;
#else
"usage: radzap [-c][-q][-d raddb][-L][-l log_dir] [-n nas][-p port] [user]\n"
"either nas or port or user must be specified\n"
"\n"
"Options are:\n"
"       -c                       Ask for confirmation before zapping.\n"
"       -d DIR                   Specify Radius configuration directory.\n"
"       -L                       Display GNU license and exit.\n"
"       -l DIR                   Specify logging directory.\n"
"       -n NASNAME               NAS from which to zap the user.\n"
"       -p PORT                  Port to zap from.\n"
"       -q                       Do not ask for confirmation before zapping.\n"
;
#endif

void
usage()
{
	printf("%s", usage_text);
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
