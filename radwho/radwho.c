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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <netinet/in.h>
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif

#include <sysdep.h>
#include <radutmp.h>
#include <radiusd.h>

#define ALIGN_LEFT    0
#define ALIGN_RIGHT   1

typedef struct {
	int      align;
	int      width;
	void     (*out)();
	char     *title;
} FORMAT;

void format_radutmp_field(char *buf, FORMAT *fmt, struct radutmp *up);
void format_radutmp_entry(FORMAT *fmt, struct radutmp *up);
void format_header(FORMAT *fmt);

void format_login(char *buf, FORMAT *fmt, struct radutmp *up);
void format_username(char *buf, FORMAT  *fmt, struct radutmp *up);
void format_date(char *buf, FORMAT *fmt, struct radutmp *up);
void format_porttype(char *buf, FORMAT *fmt, struct radutmp *up);
void format_port(char *buf, FORMAT *fmt, struct radutmp *up);
void format_nas(char *buf, FORMAT *fmt, struct radutmp *up);
void format_proto(char *buf, FORMAT *fmt, struct radutmp *up);
void format_address(char *buf, FORMAT *fmt, struct radutmp *up);
void format_orig(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_sid(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_proto(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_delay(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_type(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_time(char *buf, FORMAT *fmt, struct radutmp *ut);
void format_clid(char *buf, FORMAT *fmt, struct radutmp *ut);

NAS * my_read_naslist_file(char *file);
void local_who();
void radius_who();
void print_header();
char * time_str(char *buffer, time_t t);
char * proto(struct radutmp *rt);
char * nasname(UINT4 ipaddr);
char * hostname(UINT4 ipaddr);
void parse_fmtspec(char *str);
void set_data_format(char *s);
void set_ip_format(char *s);
void usage();
void license();

FORMAT end_fmt = { 0, 0, NULL, NULL };

FORMAT login_fmt = {
	ALIGN_LEFT,        
	10,
	format_login,
	"Login"
};

FORMAT name_fmt = {
	ALIGN_LEFT,        
	17,
	format_username,
	"Name"
};

FORMAT porttype_fmt = {
	ALIGN_LEFT,        
	1,
	format_porttype,
	"PType"
};

FORMAT port_fmt = {
	ALIGN_LEFT,        
	5,
	format_port,
	"TTY"
};

FORMAT date_fmt = {
	ALIGN_LEFT,        
	9,
	format_date,
	"When"
};

FORMAT nas_fmt = {
	ALIGN_LEFT,        
	9,
	format_nas,
	"From"
};

FORMAT address_fmt = {
	ALIGN_LEFT,        
	16,
	format_address,
	"Location"
};

FORMAT orig_fmt = {
	ALIGN_LEFT,        
	10,
	format_orig,
	"OrigLogin"
};

FORMAT sid_fmt = {
	ALIGN_LEFT,        
	16,
	format_sid,
	"Session ID"
};

FORMAT proto_fmt = {
	ALIGN_LEFT,        
	4,
	format_proto,
	"What"
};

FORMAT delay_fmt = {
	ALIGN_LEFT,        
	5,
	format_delay,
	"Delay"
};

FORMAT type_fmt = {
	ALIGN_LEFT,        
	4,
	format_type,
	"Type"
};

FORMAT time_fmt = {
	ALIGN_LEFT,        
	5,
	format_time,
	"Time"
};

FORMAT clid_fmt = {
	ALIGN_LEFT,        
	16,
	format_clid,
	"CLID"
};


#define MAX_FMT 20
FORMAT radwho_fmt[MAX_FMT];

#define OPTSTR "Acd:D:e:f:FhHiI:lLno:su"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {       
	"all",               no_argument, 0, 'A',
	"calling-id",        no_argument, 0, 'c',
	"directory",   required_argument, 0, 'd',
	"date-format", required_argument, 0, 'D',
	"empty",       required_argument, 0, 'e',
	"file",        required_argument, 0, 'f',
	"finger",            no_argument, 0, 'F',
	"help",              no_argument, 0, 'h',
	"no-header",         no_argument, 0, 'H',
	"session-id",        no_argument, 0, 'i',
	"ip-format",   required_argument, 0, 'I',
	"license",           no_argument, 0, 'L',
	"long",              no_argument, 0, 'l',
	"local-also",        no_argument, 0, 'u',
	"no-resolve",        no_argument, 0, 'n',
	"format",      required_argument, 0, 'o', 
	"secure",            no_argument, 0, 's',
	0
};
#else
# define longopt 0
# define getopt_long(ac,av,os,lo,li) getopt(ac,av,os)
#endif

#define SIP_SMART    0
#define SIP_NODOMAIN 1
#define SIP_IPADDR   2

#define SD_SMART     0
#define SD_FULL      1
#define SD_ABBR      2

int  fingerd;             /* Are we run as fingerd */
int  secure;              /* Secure mode: do not answer queries w/o username */
int  showlocal;           /* Display local users as well */
int  display_header = 1;  /* Display header line */
int  showall;             /* Display all records */
int  showip = SIP_SMART;  /* IP address display mode */
int  showdate = SD_SMART; /* Date display mode */

char *username = NULL;

char *filename = NULL;    /* radutmp filename */
char *empty = "";         /* empty field replacement */
char *eol = "\n";         /* line delimiter */
NAS  *naslist;            /* List of known NASes */

#define DEFFMT "login:10:Login,"\
               "uname:17:Name,"\
	       "proto:5:What,"\
	       "port:5:TTY,"\
	       "date:9:When,"\
	       "nas:9:From,"\
	       "ip:16:Location"

#define SIDFMT "login:10:Login,"\
               "sid:17:Session ID,"\
	       "proto:5:What,"\
	       "port:5:TTY,"\
	       "date:9:When,"\
	       "nas:9:From,"\
	       "ip:16:Location"

#define CLIDFMT "login:10:Login,"\
                "clid:17:CLID,"\
	        "proto:5:What,"\
	        "port:5:TTY,"\
	        "date:9:When,"\
	        "nas:9:From,"\
	        "ip:16:Location"

#define LONGFMT "login:32,"\
	        "sid:32,"\
	        "proto:5:Proto,"\
	        "port:5,"\
	        "date:27,"\
	        "nas:32,"\
	        "clid:17,"\
	        "time:7"

	       
char *fmtspec = NULL;

int
main(argc, argv)
	int  argc;
	char **argv;
{
	FILE *fp;
	struct radutmp rt;
	struct utmp ut;
	char inbuf[128];
	char *path;
	char *p, *q;
	int c;
	extern char *optarg;

	app_setup();
	initlog(argv[0]);
	while ((c = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF) 
	        switch(c) {
		case 'A': /* display all entries */
			showall++;
			break;
		case 'c': /* CLID instead of GECOS */
			fmtspec = estrdup(CLIDFMT);
			break;
		case 'd': /* radius directory */
			radius_dir = optarg;
			break;
		case 'D': /* Date format */
			set_data_format(optarg);
			break;
		case 'e': /* empty field replacement */
			empty = estrdup(optarg);
			break;
		case 'f': /* filename */
			filename = optarg;
			break;
		case 'F':
			fingerd++;
			break;
		case 'h':
			usage();
			exit(0);
		case 'H': /* Disable header line */
			display_header = 0;
			break;
		case 'i': /* Display SID instead of GECOS */
			fmtspec = estrdup(SIDFMT);
			break;
		case 'I': /* Ipaddr format */
			set_ip_format(optarg);
			break;
		case 'l': /* long output */
			fmtspec = estrdup(LONGFMT);
			showip = SIP_SMART;
			showdate = SD_FULL;
			break;
		case 'L':
			license();
			exit(0);
		case 'n':
			showip = SIP_IPADDR;
			break;
		case 'o':
			fmtspec = optarg;
			break;
		case 's':
			secure++;
			break;
		case 'u':
			showlocal++;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}

	radpath_init();

	if (!fmtspec)
		fmtspec = getenv("RADWHO_FORMAT");

	if (!fmtspec)
		fmtspec = estrdup(DEFFMT);
	parse_fmtspec(fmtspec);

	if (!filename)
		filename = radutmp_path;
	
	/*
	 *	Read the "naslist" file.
	 */
	path = mkfilename(radius_dir, RADIUS_NASLIST);
	if ((naslist = my_read_naslist_file(path)) == NULL)
		exit(1);


	/*
	 *	See if we are "fingerd".
	 */
	if (strstr(argv[0], "fingerd")) 
		fingerd++;

	if (fingerd) {
		eol = "\r\n";
		/*
		 *	Read first line of the input.
		 */
		fgets(inbuf, sizeof(inbuf), stdin);
		p = inbuf;
		while(*p == ' ' || *p == '\t') p++;
		if (*p == '/' && *(p + 1)) p += 2;
		while(*p == ' ' || *p == '\t') p++;
		for(q = p; *q && *q != '\r' && *q != '\n'; q++)
			;
		*q = 0;
		if (*p)
			username = p;

		/*
		 *	See if we fingered a specific user.
		 */
		if (secure && username == 0) {
			printf(_("must provide username\n"));
			exit(1);
		}
	}

	if (showlocal)
		local_who();

	radius_who();

	fflush(stdout);
	fflush(stderr);

	return 0;
}

void
set_data_format(s)
	char *s;
{
	if (strcmp(s, "short") == 0)
		showdate = SD_SMART;
	else if (strcmp(s, "full") == 0)
		showdate = SD_FULL;
	else if (strcmp(s, "abbr") == 0)
		showdate = SD_ABBR;
	else
		radlog(L_ERR, _("invalid date format: %s"), s);
}

void
set_ip_format(s)
	char *s;
{
	if (strcmp(s, "smart") == 0)
		showip = SIP_SMART;
	else if (strcmp(s, "ip") == 0)
		showip = SIP_IPADDR;
	else if (strcmp(s, "nodomain") == 0)
		showip = SIP_NODOMAIN;
	else
		radlog(L_ERR, _("invalid IP format: %s"), s);
}

void
tty_to_port(rt, tty)
	struct radutmp *rt;
	char *tty;
{
	char *p;

	p = tty + strlen(tty) - 1; 
	while (p >= tty && isdigit(*p))
		p--;
	rt->porttype = *p;
	rt->nas_port = atoi(p+1);
}

void
local_who()
{
	FILE  *fp;
	struct utmp ut;
	struct radutmp rt;
	
	if ((fp = fopen(UTMP_FILE, "r")) == NULL) {
		radlog(L_ERR, _("can't open file: %s"),
		       UTMP_FILE);
		return;
	}

	print_header();

	memset(&rt, 0, sizeof(rt));
	rt.nas_address = rt.framed_address = 0x0100007f;
	
	while(fread(&ut, sizeof(ut), 1, fp) == 1) {
#ifdef USER_PROCESS
		if (ut.ut_user[0] && ut.ut_line[0] &&
		    ut.ut_type == USER_PROCESS) {
#else
		if (ut.ut_user[0] && ut.ut_line[0]) {
#endif
			rt.type = P_CONSOLE;
			strncpy(rt.login, ut.ut_name, RUT_NAMESIZE);
			strncpy(rt.orig_login, ut.ut_host, RUT_NAMESIZE);
#ifdef __svr4__
			rt.time = ut.ut_xtime;
#else
			rt.time = ut.ut_time;
#endif
			tty_to_port(&rt, ut.ut_line);
			if (want_rad_record(&rt)) 
				format_radutmp_entry(radwho_fmt, &rt);
		}
	}
	fclose(fp);
}

void
radius_who()
{
	FILE          *fp;
	struct radutmp rt;
	print_header();

	/*
	 *	Show the users logged in on the terminal server(s).
	 */
	if ((fp = fopen(filename, "r")) == NULL)
		return ;

	while(fread(&rt, sizeof(rt), 1, fp) == 1) {
		if (want_rad_record(&rt)) 
			format_radutmp_entry(radwho_fmt, &rt);
	}
}

void
print_header()
{
	if (display_header) {
		format_header(radwho_fmt);
		display_header = 0;
	}
}

int
want_rad_record(rt)
	struct radutmp *rt;
{
	if (username && strcmp(rt->login, username))
		return 0;
	
	switch (showall) {
	case 0:
		return rt->type != P_IDLE;
	case 1:
		return rt->login[0] != 0;
	case 2:
	default:
		return (rt->type == P_IDLE && rt->login[0] != 0);
	}

	return rt->login[0] != 0;
}

/* ***************************************************************************
 * Basic output functions
 */


void
format_radutmp_field(buffer, fmt, up)
	char           *buffer;
	FORMAT         *fmt;
	struct radutmp *up;
{
	int  len;
	
	fmt->out(buffer, fmt, up);

	len = strlen(buffer);

	switch (fmt->align) {
	case ALIGN_LEFT:
		while (len < fmt->width)
			buffer[len++] = ' ';
		buffer[fmt->width] = 0;
		printf("%s", buffer);
		break;
		
	case ALIGN_RIGHT:
		if (len && len < fmt->width) {
			char *p, *q;

			p = buffer + fmt->width - 1;
			q = buffer + len - 1;
			while (q >= buffer)
				*p-- = *q--;
			while (p >= buffer)
				*p-- = ' ';
		}
		buffer[fmt->width] = 0;
		printf("%s", buffer);
	}
}

char buffer[1024]; /* FIXME */

void
format_radutmp_entry(fmt, up)
	FORMAT         *fmt;
	struct radutmp *up;
{
	for (; fmt->out; fmt++) {
		format_radutmp_field(buffer, fmt, up);
		if (fmt[1].out)
			printf(" ");
	}
	printf("%s", eol);
}

void
format_header(fmt)
	FORMAT *fmt;
{
	for (; fmt->out; fmt++) 
		printf("%*.*s", fmt->width, fmt->width, fmt->title);
	printf("%s", eol);
}

void
format_login(buf, fmt, up)
	char           *buf;
	FORMAT         *fmt;
	struct radutmp *up;
{
	strcpy(buf, up->login);
}

void
format_username(buf, fmt, up)
	char           *buf;
	FORMAT         *fmt;
	struct radutmp *up;
{
	struct passwd *pwd;
	char *s;

	if ((pwd = getpwnam(up->login)) != NULL) {
		if ((s = strchr(pwd->pw_gecos, ',')) != NULL)
			*s = 0;
		s = pwd->pw_gecos;
	} else
		s = up->login;
	strcpy(buf, s);
}

void
format_porttype(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	sprintf(buf, "%c", up->porttype);
}

void
format_port(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	sprintf(buf, "S%03d", up->nas_port);
}

/*
 *	Return a time in the form day hh:mm
 */
void
format_date(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	int len;
	
	switch (showdate) {
	case SD_SMART:
		strftime(buf, 120, "%a %H:%M", localtime(&up->time));
		break;
	case SD_FULL:
		strcpy(buf, ctime(&up->time));
		len = strlen(buf);
		if (buf[len - 1] == '\n')
			buf[len - 1] = 0;
		break;
	case SD_ABBR:
		strftime(buf, 120, "%d/%m %H:%M", localtime(&up->time));
	}
}

void
format_nas(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	if (showip == SIP_IPADDR)
		fmt->width = DOTTED_QUAD_LEN;
	strcpy(buf, nasname(up->nas_address));
}

void
format_address(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	if (showip == SIP_IPADDR)
		fmt->width = DOTTED_QUAD_LEN;
	strcpy(buf, hostname(up->framed_address));
}

void
format_orig(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	strcpy(buf, up->orig_login);
}

void format_sid(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	strcpy(buf, up->session_id);
}	

void
format_proto(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	strcpy(buf, proto(up));
}	

void
format_delay(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	time_str(buf, up->delay);
}	

void
format_type(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	sprintf(buf, "%d", up->type);
}	

void
format_time(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	time_str(buf, up->duration);
}	

void
format_clid(buf, fmt, up)
	char           *buf; 
	FORMAT         *fmt;
	struct radutmp *up;
{
	sprintf(buf, up->caller_id);
}	

/* ***************************************************************************
 * Other formatting functions
 */

char *
time_str(buffer, t)
	char   *buffer;
	time_t t;
{
	int d,h,m,s;

	d = t / 86400;
	t %= 86400;
	
	s = t % 60;
	m = t / 60;
	if (m > 59) {
		h = m / 60;
		m -= h*60;
	} else
		h = 0;
	if (d)
		sprintf(buffer, "%d+%02d:%02d", d, h, m);
	else
		sprintf(buffer, "%02d:%02d", h, m);
	return buffer;
}

char *
proto(rt)
	struct radutmp *rt;
{
	if (rt->type == P_IDLE)
		return "HUP";
	switch (rt->proto) {
	case 'S':
		return "SLIP";
	case 'P':
		return "PPP";
	}
	return "shell";
}	 

/*
 *	Find name of NAS
 */
char *
nasname(ipaddr)
	UINT4 ipaddr;
{
	NAS *cl;
	UINT4 ip;
	
	if (showip != SIP_SMART)
		return hostname(ipaddr);

	ip = ntohl(ipaddr);
	for(cl = naslist; cl; cl = cl->next)
		if (cl->ipaddr == ip)
			break;
	if (cl == NULL)
		return hostname(ipaddr);
	if (cl->shortname[0])
		return cl->shortname;
	return cl->longname;
}


/*
 *	Print address of NAS.
 */
char *
hostname(ipaddr)
	UINT4 ipaddr;
{
	char *s, *p;
	static char ipbuf[DOTTED_QUAD_LEN];
	
	if (ipaddr == 0 || ipaddr == (UINT4)-1 || ipaddr == (UINT4)-2)
		return empty;

	switch (showip) {
	case SIP_SMART:
		return ip_hostname(ntohl(ipaddr));
	case SIP_NODOMAIN:
		s = ip_hostname(ntohl(ipaddr));
		for (p = s; *p && (isdigit(*p) || *p == '.'); p++)
			;
		if (*p == 0)
			return s;
		if ((p = strchr(s, '.')) != NULL)
			*p = 0;
		return s;
	case SIP_IPADDR:
		ipaddr2str(ipbuf, ntohl(ipaddr));
		return ipbuf;
	}
}

/* ***************************************************************************
 * Functions for parsing format spec
 */
typedef struct {
	char    *name;
	FORMAT  *fmt;
} Keyword;

Keyword kwd[] = {
	"login",  &login_fmt,
	"orig",   &orig_fmt,
	"port",   &port_fmt,
	"sid",    &sid_fmt,
	"nas",    &nas_fmt,
	"ip",     &address_fmt,
	"proto",  &proto_fmt,
	"date",   &date_fmt,
	"delay",  &delay_fmt,
	"type",   &type_fmt,
	"ptype",  &porttype_fmt,
	"time",   &time_fmt,
	"clid",   &clid_fmt,
	"uname",  &name_fmt
};

#define NKW sizeof(kwd)/sizeof(kwd[0])

FORMAT *
lookup_kw(name)
	char *name;
{
	Keyword *kp;

	for (kp = kwd; kp < kwd + NKW; kp++)
		if (strcmp(kp->name, name) == 0)
			return kp->fmt;
	return NULL;
}

void
parse_fmtspec(str)
	char *str;
{
	FORMAT *fmt, *fp;
	char *p;
	int nfmt = 0;
	int c;
	
	while (*str) {
		if (nfmt >= MAX_FMT) {
			radlog(L_ERR,
			       _("too many format specs"));
			exit(1);
		}
		
		fp = &radwho_fmt[nfmt++];

		p = str;
		while (*p && !(*p == ':' || *p == ','))
			p++;
		if (*p) {
			c = *p;
			*p++ = 0;
		} else
			c = 0;

		if ((fmt = lookup_kw(str)) == NULL) {
			radlog(L_ERR,
			       _("no such format name: %s"), str);
			exit(1);
		}

		*fp = *fmt;

		if (c == ':') {
			if (*p == '+') {
				fp->align = ALIGN_RIGHT;
				p++;
			} else if (*p == '-') {
				fp->align = ALIGN_LEFT;
				p++;
			}
			fp->width = strtol(p, &p, 10);
			if (*p == ':') {
				str = ++p;
				while (*p && *p != ',')
					p++;
				if (*p)
					*p++ = 0;
				fp->title = estrdup(str);
			} else if (*p != ',' && *p != 0) {
				radlog(L_ERR,
				       _("error in format spec near %s"),
				       p);
				exit(1);
			} else if (*p == ',')
				p++;
		}
		str = p;
	}
	radwho_fmt[nfmt] = end_fmt;
}

/* ***************************************************************************
 */

/*
 *	Read the naslist file.
 */
NAS *
my_read_naslist_file(file)
	char *file;
{
	FILE	*fp;
	char	buffer[256];
	char	hostnm[128];
	char	shortnm[32];
	char	nastype[32];
	int	lineno = 0;
	NAS	*cl = NULL;
	NAS	*c;

	if ((fp = fopen(file, "r")) == NULL) {
		fprintf(stderr, _("can't open %s"), file);
		fprintf(stderr, "\n");
		return NULL;
	}
	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		shortnm[0] = 0;
		if (sscanf(buffer, "%s%s%s", hostnm, shortnm, nastype) < 2) {
			fprintf(stderr, _("%s:%d: syntax error\n"), file, lineno);
			continue;
		}
		c = Alloc_entry(NAS);

		c->ipaddr = get_ipaddr(hostnm);
		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));

		c->next = cl;
		cl = c;
	}
	fclose(fp);

	return cl;
}

/* ***************************************************************************
 *
 */

char usage_str[] =
#ifdef HAVE_GETOPT_LONG
"usage: radwho [options] username\n"
"Options are:\n"
"       -A, --all            Print all entries, not only active ones.\n" 
"       -c, --calling-id     Display CLID in second column.\n"
"       -D, --date-format {short|abbr|full}\n"
"                            Change date representation format.\n"
"       -d, --directory DIR  Specify Radius configuration directory.\n"
"       -e, --empty STRING   Print STRING instead of an empty column.\n"
"       -F, --finger         Act as a finger daemon.\n"
"       -f, --file FILE      Use FILE instead of /var/log/radwtmp\n"
"       -H, --no-header      Do not display header line.\n"
"       -h, --help           Display this help.\n"
"       -i, --session-id     Display session ID in the second column.\n"
"       -I, --ip-format {smart|ip|nodomain}\n"
"                            Change IP address representation format.\n"
"       -L, --license        Display GNU license and exit\n"
"       -l, --long           Long output. All fields will be printed.\n"
"                            Implies -D full -I smart.\n"
"       -n, --no-resolve     Do not resolve hostnames. The same as -I ip.\n"
"       -o, --format         Specify format line.\n"
"       -s, --secure         Secure mode: requires that the username be\n"
"                            specified.\n"
"       -u, --local-also     Display also local users.\n";
#else
"usage: radwho [options] username\n"
"Options are:\n"
"       -A                   Print all entries, not only active ones.\n" 
"       -c                   Display CLID in second column.\n"
"       -D {short|abbr|full}\n"
"                            Change date representation format.\n"
"       -d DIR               Specify Radius configuration directory.\n"
"       -e STRING            Print STRING instead of an empty column.\n"
"       -F                   Act as a finger daemon.\n"
"       -f FILE              Use FILE instead of /var/log/radwtmp\n"
"       -H                   Do not display header line.\n"
"       -h                   Display this help.\n"
"       -i                   Display session ID in the second column.\n"
"       -I {smart|ip|nodomain}\n"
"                            Change IP address representation format.\n"
"       -L                   Display GNU license and exit.\n"
"       -l                   Long output. All fields will be printed.\n"
"                            Implies -D full -I smart.\n"
"       -n                   Do not resolve hostnames. The same as -I ip.\n"
"       -o                   Specify format line.\n"
"       -s                   Secure mode: requires that the username be\n"
"                            specified.\n"
"       -u                   Display also local users.\n";
#endif

void
usage()
{
	printf("%s", usage_str);
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
