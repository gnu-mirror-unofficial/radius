/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_RADIUSD_C

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include <getopt1.h>
#include <radiusd.h>
#include <radsql.h>
#include <log.h>
#include <symtab.h>
#include <radutmp.h>
#include <rewrite.h>
#ifdef USE_SERVER_GUILE
# include <libguile.h>
#endif

/* ********************** Request list handling **************************** */
	
typedef struct request {
	struct request *next;         /* Link to the next request */
	int             type;         /* request type */
	time_t          timestamp;    /* when was the request accepted */
	pthread_t       child_pid;    /* ID of the handling process (or -1) */
	int             child_return; /* Child return code if child_pid=NULL */
	void           *data;         /* Request-specific data */
} REQUEST;

void rad_req_free(RADIUS_REQ *req);
void rad_req_drop(int type, RADIUS_REQ *ptr, char *status_str);
int radreq_cmp(RADIUS_REQ *a, RADIUS_REQ *b);

struct request_class request_class[] = {
	{ "AUTH", 0, MAX_REQUEST_TIME, CLEANUP_DELAY, 1,
	  rad_authenticate, NULL, radreq_cmp, rad_req_free,
	  rad_req_drop, NULL, rad_sql_cleanup },
	{ "ACCT", 0, MAX_REQUEST_TIME, CLEANUP_DELAY, 1,
	  rad_accounting, rad_acct_xmit, radreq_cmp, rad_req_free,
	  rad_req_drop, NULL, rad_sql_cleanup },
	{ "PROXY",0, MAX_REQUEST_TIME, CLEANUP_DELAY, 0,
	  rad_proxy, NULL, radreq_cmp, rad_req_free,
	  rad_req_drop, NULL, NULL },
#ifdef USE_SNMP
	{ "SNMP", 0, MAX_REQUEST_TIME, 0, 1,
	  snmp_answer, NULL, snmp_req_cmp, snmp_req_free,
	  snmp_req_drop, NULL, NULL }
#endif
};

/* the request queue */
static REQUEST		*first_request;
pthread_mutex_t request_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#define request_list_block() \
 pthread_mutex_lock(&request_list_mutex);
#define request_list_unblock() \
 pthread_mutex_unlock(&request_list_mutex)
	
static void request_free(REQUEST *req);
static void request_drop(int type, void *data, char *status_str);
static void request_xmit(int type, int code, void *data, int fd);
void rad_handle_request(int type, void *data, int activefd);
static int flush_request_list();
static int request_setup(int type, void *data);
static void request_cleanup(int type, void *data);

static void unlink_pidfile();

/* ************************ Socket control queue ************************** */

struct socket_list {
	struct socket_list *next;
	int fd;
	int (*success)(struct sockaddr *, int);
	int (*respond)(int fd, struct sockaddr *, int, u_char *, int);
	int (*failure)(struct sockaddr *, int);
};

static struct socket_list *socket_first;
static int max_fd;
static void add_socket_list(int fd, int (*s)(), int (*r)(), int (*f)());
static void close_socket_list();
static void rad_select();
static void rad_main();

/* Implementation functions */
int auth_respond(int fd, struct sockaddr *sa, int salen,
		 u_char *buf, int size);
int acct_success(struct sockaddr *sa, int salen);
int acct_failure(struct sockaddr *sa, int salen);
int snmp_respond(int fd, struct sockaddr *sa, int salen,
		 u_char *buf, int size);

/* *************************** Global variables. ************************** */

char	   *progname;

int        debug_flag; /* can be raised from debugger only */
int        log_mode;

static int foreground; /* Stay in the foreground */
static int spawn_flag; 
int use_dbm = 0;
int open_acct = 1;
int auth_detail = 0;
int acct_detail = 1;      
int strip_names;
int suspend_flag;
#ifdef USE_SNMP
serv_stat saved_status;
#endif

Config config = {
	1,               /* checkrad_assume_logged */
	MAX_REQUESTS,    /* maximum number of requests */
	NULL,            /* exec_program_user */
};

UINT4 warning_seconds;
int use_guile;
char *message_text[MSG_COUNT];

UINT4 myip = INADDR_ANY;
int auth_port;
int acct_port;
#ifdef USE_SNMP
int snmp_port;
#endif


/* Make sure recv_buffer is aligned properly. */
static int i_recv_buffer[RAD_BUFFER_SIZE];
static u_char *recv_buffer = (u_char *)i_recv_buffer;

pthread_t radius_tid; /* The PID of the main process */
pthread_attr_t thread_attr;

static int need_reload = 0;  /* the reload of the configuration is needed */
static int need_restart = 0; /* try to restart ourselves when set to 1 */

static void check_reload();

static void set_config_defaults();
static void usage(void);
void rad_exit(int);
static RETSIGTYPE sig_fatal (int);
static RETSIGTYPE sig_hup (int);
static RETSIGTYPE sig_usr1 (int);
static RETSIGTYPE sig_dumpdb (int);

static int radrespond (RADIUS_REQ *, int);
static void *radrespond0(void *);

static int open_socket(UINT4 ipaddr, int port, char *type);
static void open_socket_list(HOSTDECL *hostlist, int defport, char *descr,
			     int (*s)(), int (*r)(), int (*f)());

static void reread_config(int reload);

#define OPTSTR "Aa:bd:fhl:Lm:Nni:p:P:Ssvx:yz"

struct option longopt[] = {
	"log-auth-detail",    no_argument,       0, 'A',
	"acct-directory",     required_argument, 0, 'a',
#ifdef USE_DBM
	"dbm",                no_argument,       0, 'b',
#endif
	"directory",          required_argument, 0, 'd',
	"config-directory",   required_argument, 0, 'd',
	"foreground",         no_argument,       0, 'f',
	"help",               no_argument,       0, 'h', 
	"logging-directory",  no_argument,       0, 'l',
	"license",            no_argument,       0, 'L',
	"mode",               required_argument, 0, 'm',
	"auth-only",          no_argument,       0, 'N',
	"do-not-resolve",     no_argument,       0, 'n',
	"ip-address",	      required_argument, 0, 'i',	
	"port",               required_argument, 0, 'p',
	"pid-file-dir",       required_argument, 0, 'P',
	"log-stripped-names", no_argument,       0, 'S',
	"single-process",     no_argument,       0, 's',
	"version",            no_argument,       0, 'v',
	"debug",              required_argument, 0, 'x',
	"log-auth",           no_argument,       0, 'y',
	"log-auth-pass",      no_argument,       0, 'z',
	0
};

int radius_mode = MODE_DAEMON;    

int  xargc;
char **xargv;
char *x_debug_spec;

int
main(argc, argv)
	int argc;
	char **argv;
{
	struct servent *svp;
	int radius_port = 0;
	int t;

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	/* debug_flag can be set only from debugger.
	   It means developer is taking control in his hands, so
	   we won't modify any variables that could prevent him
	   from doing so. */
	if (debug_flag == 0) {
		foreground = 0;
		spawn_flag = 1;
	}

	app_setup();

	/* save the invocation */
	xargc = argc;
	xargv = argv;

	/* Set up some default values */
	set_config_defaults();

	/* Process the options.	 */
	while ((t = getopt_long(argc, argv, OPTSTR, longopt, NULL)) != EOF) {
		switch (t) {
		case 'A':
			auth_detail++;
			break;
		case 'a':
			radacct_dir = make_string(optarg);
			break;
#ifdef USE_DBM
		case 'b':
			use_dbm++;
			break;
#endif
		case 'd':
			radius_dir = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'L':
			license();
			exit(0);
		case 'l':
			radlog_dir = make_string(optarg);
			break;
		case 'm':
			switch (optarg[0]) {
			case 't':
				radius_mode = MODE_TEST;
				break;
			case 'b':
#ifdef USE_DBM
				radius_mode = MODE_BUILDDBM;
#else
				fprintf(stderr,
				    _("radiusd compiled without DBM support"));
				exit(1);
#endif
				break;
			case 'c':
				radius_mode = MODE_CHECKCONF;
				break;
			default:
				radlog(L_ERR,
				       _("unknown mode: %s"), optarg);
			}
			break;
		case 'N':
			open_acct = 0;
			break;
		case 'n':
			resolve_hostnames = 0;
			break;
		case 'i':
			if ((myip = ip_gethostaddr(optarg)) == 0)
				fprintf(stderr,
					_("invalid IP address: %s"),
					optarg);
			break;
		case 'P':
			radpid_dir = optarg;
			break;
		case 'p':
			radius_port = atoi(optarg);
			break;
		case 'S':
			strip_names++;  
			break;
		case 's':	/* Single process mode */
			spawn_flag = 0;
			break;
		case 'v':
			version();
			break;
		case 'x':
			x_debug_spec = optarg;
			set_debug_levels(optarg);
			break;
		case 'y':
			log_mode |= RLOG_AUTH;    
			break;
		case 'z':
			log_mode |= RLOG_AUTH_PASS;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}
	radpath_init();

	log_set_default("default.log", -1, -1);
	if (radius_mode != MODE_DAEMON)
		log_set_to_console();
	
	signal(SIGHUP, sig_hup);
	signal(SIGQUIT, sig_fatal);
	signal(SIGTERM, sig_fatal);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGBUS, sig_fatal);
	signal(SIGTRAP, sig_fatal);
	signal(SIGFPE, sig_fatal);
	signal(SIGSEGV, sig_fatal);
	signal(SIGILL, sig_fatal);
	/* Do not handle SIGIOT, please! */

	if (!foreground && radius_mode != MODE_CHECKCONF)
		signal(SIGINT, sig_dumpdb);
	else
		signal(SIGINT, sig_fatal);
	
	for (t = getmaxfd(); t >= 3; t--)
		close(t);

	/* Determine default port numbers for authentication and accounting */
	if (radius_port)
		auth_port = radius_port;
	else {
		svp = getservbyname ("radius", "udp");
		if (svp != (struct servent *) 0)
			auth_port = ntohs(svp->s_port);
		else
			auth_port = DEF_AUTH_PORT;
	}
	if (radius_port ||
	    (svp = getservbyname ("radacct", "udp")) == (struct servent *) 0)
		acct_port = auth_port + 1;
	else
		acct_port = ntohs(svp->s_port);

	snmp_init(0, 0, emalloc, efree);

	rad_main(argv[optind]);
}

void
set_config_defaults()
{
        config.exec_user  = make_string("daemon");
        username_valid_chars = make_string(".-_!@#$%^&\\/");
	message_text[MSG_ACCOUNT_CLOSED] =
		make_string("Sorry, your account is currently closed\r\n");
	message_text[MSG_PASSWORD_EXPIRED] =
		make_string("Password Has Expired\r\n");
	message_text[MSG_PASSWORD_EXPIRE_WARNING] =
		make_string("Password Will Expire in %R{Password-Expire-Days} Days\r\n");
	message_text[MSG_ACCESS_DENIED] =
		make_string("\r\nAccess denied\r\n");
	message_text[MSG_REALM_QUOTA] =
		make_string("\r\nRealm quota exceeded - access denied\r\n");
	message_text[MSG_MULTIPLE_LOGIN] =
		make_string("\r\nYou are already logged in %R{Simultaneous-Use} times - access denied\r\n");
	message_text[MSG_SECOND_LOGIN] =
		make_string("\r\nYou are already logged in - access denied\r\n");
	message_text[MSG_TIMESPAN_VIOLATION] =
		make_string("You are calling outside your allowed timespan\r\n");
}

void
rad_daemon()
{
	FILE *fp;
	char *p;
	int t;
	pid_t pid;
	
	switch (pid = fork()) {
	case -1:
		radlog(L_CRIT, _("couldn't fork: %s"), strerror(errno));
		exit(1);
	case 0: /* Child */
		break;
	default: /* Parent */
		exit(0);
	}
		
#ifdef HAVE_SETSID
	setsid();
#endif
	/* SIGHUP is ignored because when the session leader terminates
	   all process in the session are sent the SIGHUP.  */
	signal (SIGHUP, SIG_IGN);

	/* fork() again so the parent, can exit. This means that we, as a
	   non-session group leader, can never regain a controlling
	   terminal. */
	switch (pid = fork()) {
	case 0:
		break;
	case -1:
		radlog(L_CRIT, _("couldn't fork: %s"), strerror(errno));
		exit(1);
	default:
		exit(0);
	}

	chdir("/tmp");/*FIXME*/
	umask(022);
	
	pid = getpid();
	p = mkfilename(radpid_dir, "radiusd.pid");
	if ((fp = fopen(p, "w")) != NULL) {
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	}
	efree(p);

	/* FIXME: This is needed for messages generated by guile
	   functions. */
	p = mkfilename(radlog_dir, "radius.stderr");
	t = open(p, O_CREAT|O_WRONLY, 0644);
	if (t != -1) {
		if (t != 2) 
			dup2(t, 2);
		if (t != 1) 
			dup2(t, 1);
		if (t != 1 && t != 2)
			close(t);
		fflush(stdout);
		fflush(stderr);
	}
	efree(p);
}

void
common_init()
{
#ifdef HAVE_SETVBUF
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif
	radius_tid = pthread_self();
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#ifdef USE_SERVER_GUILE
	start_guile();
#endif
	reread_config(0);
}	

void
rad_main(extra_arg)
	char *extra_arg;
{
	switch (radius_mode) {
	case MODE_CHECKCONF:
		common_init();
		exit(0);

	case MODE_TEST:
		common_init();
		exit(test_shell());
		
#ifdef USE_DBM		
	case MODE_BUILDDBM:
		common_init();
		exit(builddbm(extra_arg));
#endif
	case MODE_DAEMON:
#ifdef USE_SNMP
		snmp_tree_init();
#endif
		if (!foreground)
			rad_daemon();
		common_init();
	}

	radlog(L_INFO, _("Ready to process requests."));

	for(;;) {
		check_reload();
		rad_sql_idle_check(); 
		rad_select();
	}
	/*NOTREACHED*/
}

void
unlink_pidfile()
{
	char *p = mkfilename(radpid_dir, "radiusd.pid");
	unlink(p);
	efree(p);
}

/* Open authentication sockets. */
void
listen_auth(list)
	HOSTDECL *list;
{
	if (radius_mode != MODE_DAEMON)
		return;
	open_socket_list(list, auth_port, "auth", NULL, auth_respond, NULL);
}

/* Open accounting sockets. */
void
listen_acct(list)
	HOSTDECL *list;
{
	if (!open_acct || radius_mode != MODE_DAEMON)
		return;
	open_socket_list(list, acct_port, "acct",
			 acct_success, auth_respond, acct_failure);
}

void
add_socket_list(fd, s, r, f)
	int fd;
	int (*s)();
	int (*r)();
	int (*f)();
{
	struct socket_list      *ctl;

	ctl = alloc_entry(sizeof(struct socket_list));
	ctl->fd = fd;
	if (fd + 1 > max_fd)
		max_fd = fd + 1;
	ctl->success = s;
	ctl->respond = r;
	ctl->failure = f;
	ctl->next = socket_first;
	socket_first = ctl;
}

void
close_socket_list()
{
	struct socket_list *next;
	while (socket_first) {
		next = socket_first->next;
		close(socket_first->fd);
		free_entry(socket_first);
		socket_first = next;
	}
	max_fd = 0;
}

void
rad_select()
{
	int result;
	int status;
	int salen;
	struct sockaddr	saremote;
	fd_set readfds;
	struct socket_list *ctl;
	struct timeval tv;
	
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	FD_ZERO(&readfds);
	for (ctl = socket_first; ctl; ctl = ctl->next) 
		FD_SET(ctl->fd, &readfds);

	status = select(max_fd, &readfds, NULL, NULL, &tv);

	if (status == -1) {
		if (errno == EINTR) 
			return;/* give main a chance to do some housekeeping */
		rad_exit(101);
	/* If a timeout occurs, then just return to main for housekeeping */
	} else if (status == 0) {
		return;
	}
	
	for (ctl = socket_first; ctl; ctl = ctl->next) {
		if (FD_ISSET(ctl->fd, &readfds)) {
			salen = sizeof (saremote);
			result = recvfrom (ctl->fd, (char *) recv_buffer,
					       (int) sizeof(i_recv_buffer),
					       (int) 0, &saremote, &salen);

			if (ctl->success)
				ctl->success(&saremote, salen);
			if (result > 0) {
				ctl->respond(ctl->fd,
					     &saremote, salen,
					     recv_buffer, result);
			} else if (result < 0 && errno == EINTR) {
				if (ctl->failure)
					ctl->failure(&saremote, salen);
				result = 0;
			}
		}
	}
}

/* ************************* Socket queue functions *********************** */
/*ARGSUSED*/
int
auth_respond(fd, sa, salen, buf, size)
	int fd;
	struct sockaddr *sa;
	int salen;
	u_char *buf;
	int size;
{
	RADIUS_REQ *radreq;
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	
	radreq = radrecv(ntohl(sin->sin_addr.s_addr),
			 ntohs(sin->sin_port),
			 buf,
			 size);
	if (radrespond(radreq, fd))
		radreq_free(radreq);
	return 0;
}

int
acct_success(sa, salen)
	struct sockaddr *sa;
	int salen;
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	stat_inc(acct, ntohl(sin->sin_addr.s_addr), num_req);
	return 0;
}

int
acct_failure(sa, salen)
	struct sockaddr *sa;
	int salen;
{
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	stat_inc(acct, ntohl(sin->sin_addr.s_addr), num_bad_req);
	return 0;
}

#ifdef USE_SNMP

void *
snmp_respond0(arg)
	void *arg;
{
	struct snmp_req *req = (struct snmp_req *)arg;
	sigset_t sig;
	
	sigemptyset(&sig);
	pthread_sigmask(SIG_SETMASK, &sig, NULL);
	rad_handle_request(R_SNMP, req, req->fd);
	return NULL;
}

int
snmp_respond(fd, sa, salen, buf, size)
	int fd;
	struct sockaddr *sa;
	int salen;
	u_char *buf;
	int size;
{
	struct snmp_req *req;
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	
	if (req = rad_snmp_respond(buf, size, sin)) {
		pthread_t tid;
		int rc;

		req->fd = fd;
		rc = pthread_create(&tid, &thread_attr, snmp_respond0, req);
		if (rc) {
			radlog(L_ERR, _("Can't spawn new thread: %s"), 
			       strerror(rc));
			return -1;
		}
	}
	return 0;
}

#endif

void
rad_susp()
{
	suspend_flag = 1;
}

void
rad_cont()
{
	suspend_flag = 0;
#ifdef USE_SNMP
	server_stat.auth.status = serv_running;
	server_stat.acct.status = serv_running;
#endif	
}
/* ************************************************************************  */

/*
 *	Read config files.
 */
void
reread_config(reload)
	int reload;
{
	int res = 0;
	int pid = getpid();
	
	if (!reload) {
		radlog(L_INFO, _("Starting - reading configuration files ..."));
	} else {
		radlog(L_INFO, _("Reloading configuration files."));
		rad_flush_queues();
		close_socket_list();
	}

#ifdef USE_SNMP
	server_stat.auth.status = serv_init;
	server_stat.acct.status = serv_init;
#endif	

	/* Read the options */
	get_config();
	if (!reload) {
		if (x_debug_spec)
			set_debug_levels(x_debug_spec);
		radpath_init();
		stat_init();
	}

#ifdef USE_SNMP
	if (radius_mode == MODE_DAEMON) {
		int fd = open_socket(myip, snmp_port, "SNMP");
		set_nonblocking(fd);
		add_socket_list(fd, NULL, snmp_respond, NULL);
	}
#endif
	
	res = reload_config_file(reload_all);
	
#ifdef USE_SNMP
	
	server_stat.auth.status = suspend_flag ?
		                                serv_suspended : serv_running;
	snmp_auth_server_reset();

	server_stat.acct.status = server_stat.auth.status;
	snmp_acct_server_reset();
		
	saved_status = server_stat.auth.status;
		
#endif	

	if (res != 0) {
		radlog(L_CRIT,
		       _("Errors reading config file - EXITING"));
		exit(1);
	}

}

/*
 *	Find out my own IP address (or at least one of them).
 */
UINT4
getmyip()
{
	char *name;
	int name_len = 256;
	UINT4 ip;
	int status;
	
	name = emalloc(name_len);
	while (name
	       && (status = gethostname(name, name_len)) == 0
	       && !memchr(name, 0, name_len)) {
		name_len *= 2;
		name = erealloc(name, name_len);
	}
	if (status) {
		radlog(L_CRIT, _("can't find out my own IP address"));
		exit(1);
	}
		
	ip = ip_gethostaddr(name);
	efree(name);
	return ip;
}

void
schedule_restart()
{
	need_restart = 1;
}

void
check_reload()
{
	if (need_restart)
		rad_restart();
	
	if (need_reload) {
		reread_config(1);
		need_reload = 0;
	}
#ifdef USE_SNMP
	else if (server_stat.auth.status != saved_status) {
		switch (server_stat.auth.status) {
		case serv_reset: /* Hard reset */
			if (xargv[0][0] != '/') {
				radlog(L_NOTICE,
				       _("can't restart: radiusd not started as absolute pathname"));
				break;
			}
			schedule_restart();
			break;
		
		case serv_init:
			reread_config(1);
			break;

		case serv_running:
			if (suspend_flag) {
				suspend_flag = 0;
				radlog(L_NOTICE, _("RADIUSD RUNNING"));
				rad_cont();
			}
			break;
			
		case serv_suspended:
			if (!suspend_flag) {
				radlog(L_NOTICE, _("RADIUSD SUSPENDED"));
				rad_susp();
			}
			break;
			
		case serv_shutdown:
			rad_flush_queues();
			rad_exit(SIGTERM);
			break;
		}
		saved_status = server_stat.auth.status;
	}
#endif		
}	

/* Respond to supported requests:
   RT_AUTHENTICATION_REQUEST - Authentication request from
                               a client network access server.
   RT_ACCOUNTING_REQUEST -     Accounting request from
                               a client network access server.

   RT_AUTHENTICATION_ACK
   RT_AUTHENTICATION_REJECT
   RT_ACCOUNTING_RESPONSE -    Reply from a remote Radius server.
                               Relay reply back to original NAS. */

int
radrespond(radreq, activefd)
	RADIUS_REQ *radreq;
	int activefd;
{
	
	if (suspend_flag)
		return 1;
	
	if (validate_client(radreq)) {
		/*FIXME: update stats */
		return -1;
	}

	/* Check if we support this request */
	switch (radreq->code) {
	case RT_AUTHENTICATION_REQUEST:
	case RT_ACCOUNTING_REQUEST:
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCOUNTING_RESPONSE:
#if defined(RT_ASCEND_EVENT_REQUEST) 		
	case RT_ASCEND_EVENT_REQUEST:
#endif
		break;
	default:
		stat_inc(acct, radreq->ipaddr, num_unknowntypes);
		radlog(L_NOTICE, _("unknown request %d"), radreq->code); 
		return -1;
	}	
	
	/* Copy the static data into malloc()ed memory. */
	radreq->data = emalloc(radreq->data_len);
	memcpy(radreq->data, recv_buffer, radreq->data_len);
	radreq->data_alloced = 1;
	radreq->fd = activefd;

	if (spawn_flag) {
		pthread_t tid;

		int rc = pthread_create(&tid, &thread_attr,
					radrespond0, radreq);
		if (rc) {
			radlog(L_ERR, _("Can't spawn new thread: %s"),
			       strerror(rc));
			return -1;
		}
	} else
		radrespond0(radreq);
	return 0;
}

void *
radrespond0(arg)
	void *arg;
{
	RADIUS_REQ *radreq = (RADIUS_REQ *)arg;
	int type = -1;
	sigset_t sig;
	
	sigemptyset(&sig);
	pthread_sigmask(SIG_SETMASK, &sig, NULL);
	
	/* First, see if we need to proxy this request. */
	switch (radreq->code) {

	case RT_AUTHENTICATION_REQUEST:
		/*
		 *	Check request against hints and huntgroups.
		 */
		stat_inc(auth, radreq->ipaddr, num_access_req);
		if (rad_auth_init(radreq, radreq->fd) < 0) {
			radreq_free(radreq);
			return NULL;
		}
		/*FALLTHRU*/
	case RT_ACCOUNTING_REQUEST:
		if (avl_find(radreq->request, DA_USER_NAME) == NULL)
			break;
		if (proxy_send(radreq, radreq->fd) != 0) {
			rad_handle_request(R_PROXY, radreq, radreq->fd);
			return NULL;
		}
		break;

	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCOUNTING_RESPONSE:
		if (proxy_receive(radreq, radreq->fd) < 0) {
			radreq_free(radreq);
			return NULL;
		}
		break;
	}

	/*
	 *	Select the required function and indicate if
	 *	we need to fork off a child to handle it.
	 */
	switch (radreq->code) {

	case RT_AUTHENTICATION_REQUEST:
		rad_sql_check_connect(SQL_AUTH);
		type = R_AUTH;
		break;
	
	case RT_ACCOUNTING_REQUEST:
	case RT_ASCEND_EVENT_REQUEST:
		rad_sql_check_connect(SQL_ACCT);
		type = R_ACCT;
		break;
		
	default:
		__insist_failure("Request type", __FILE__, __LINE__);
	}

	rad_handle_request(type, radreq, radreq->fd);
	return NULL;
}

/* *********************** Request list handling ************************** */

void
request_free(req)
	REQUEST *req;
{
	request_class[req->type].free(req->data);
	free_entry(req);
}

void
request_drop(type, data, status_str)
	int type;
	void *data;
	char *status_str;
{
	request_class[type].drop(type, data, status_str);
	request_class[type].free(data);
}

void
request_xmit(type, code, data, fd)
	int type;
	int code;
	void *data;
	int fd;
{
	if (request_class[type].xmit) 
		request_class[type].xmit(type, code, data, fd);
	else 
		request_class[type].drop(type, data, _("duplicate request"));

	switch (type) {
	case R_AUTH:
		stat_inc(auth, ((RADIUS_REQ*)data)->ipaddr, num_dup_req);
		break;
	case R_ACCT:
		stat_inc(acct, ((RADIUS_REQ*)data)->ipaddr, num_dup_req);
	}

	request_class[type].free(data);
}

int
request_cmp(type, a, b)
	int type;
	void *a, *b;
{
	return request_class[type].comp(a, b);
}

int
request_setup(type, data)
	int type;
	void *data;
{
	if (request_class[type].setup) 
		return request_class[type].setup(type, data);
	return 0;
}

void
request_cleanup(type, data)
	int type;
	void *data;
{
	if (request_class[type].cleanup)
		request_class[type].cleanup(type, data);
}

void *
scan_request_list(type, handler, closure)
	int type;
	int (*handler)();
	void *closure;
{
	REQUEST	*curreq;

	for (curreq = first_request; curreq; curreq = curreq->next) {
		if (curreq->type == type &&
		    handler(closure, curreq->data) == 0)
			return curreq->data;
	}
	return NULL;
}

void
rad_cleanup_thread(arg)
	void *arg;
{
	REQUEST *curreq = arg;
	debug(2, ("cleaning up request %lu", curreq->child_pid));
	curreq->child_pid = 0;
	curreq->timestamp = time(NULL);
	request_cleanup(curreq->type, curreq->data);
}

/* Handle the incoming request. This function also
   cleans up complete child requests, and verifies that there
   is only one process responding to each request (duplicate
   requests are filtered out). */
void
rad_handle_request(type, data, activefd)
	int type;           /* Type of request */
	void *data;         /* Request-specific data */
	int activefd;
{
	REQUEST	*curreq;
	REQUEST	*prevreq;
	REQUEST *to_replace;
	UINT4	curtime;
	int	request_count, request_type_count;

	curtime = (UINT4)time(NULL);
	request_count = request_type_count = 0;
	curreq = first_request;
	prevreq = NULL;
	to_replace = NULL; 

	/* Block asynchronous access to the list */
	request_list_block();

	while (curreq != NULL) {

		if (curreq->child_pid == 0
		    && curreq->timestamp + 
		        request_class[curreq->type].cleanup_delay <= curtime) {
			/*
			 *	Request completed, delete it
			 */
			debug(1, ("deleting completed %s request",
				 request_class[curreq->type].name));
			if (prevreq == NULL) {
				first_request = curreq->next;
				request_free(curreq);
				curreq = first_request;
			} else {
				prevreq->next = curreq->next;
				request_free(curreq);
				curreq = prevreq->next;
			}
			continue;
		}
 
		if (curreq->type == type
		    && request_cmp(type, curreq->data, data) == 0) {
			/* This is a duplicate request.
			   If the handling process has already finished --
			   retransmit it's results, if possible.
			   Otherwise just drop the request. */
			if (curreq->child_pid == 0) 
				request_xmit(type, curreq->child_return, data,
					     activefd);
			else
				request_drop(type, data,
					     _("duplicate request"));
			request_list_unblock();

			return;
		} else {
			if (curreq->timestamp +
			    request_class[curreq->type].ttl <= curtime
			    && curreq->child_pid != 0) {
				/* This request seems to have hung */
				radlog(L_NOTICE,
				     _("Killing unresponsive %s child pid %d"),
				       request_class[curreq->type].name,
				       curreq->child_pid);
				pthread_cancel(curreq->child_pid);
				curreq = curreq->next;
				continue;
			}
			if (curreq->type == type) {
				request_type_count++;
				if (type != R_PROXY
				    && curreq->child_pid == 0
				    && (to_replace == NULL
					|| to_replace->timestamp >
					                   curreq->timestamp))
					to_replace = curreq;
			}
			request_count++;
			prevreq = curreq;
			curreq = curreq->next;
		}
	}

	/* This is a new request */
	if (request_count >= config.max_requests) {
		if (!to_replace) {
			request_drop(type, data,
				     _("too many requests in queue"));

			request_list_unblock();
			return;
		}
	} else if (request_class[type].max_requests
		   && request_type_count >= request_class[type].max_requests) {
		if (!to_replace) {
			request_drop(type, data,
				     _("too many requests of this type"));

			request_list_unblock();
			return;
		}
	} else
		to_replace = NULL;

	/* First, setup the request
	 */
	if (request_setup(type, data)) {
		request_drop(type, data, _("request setup failed"));
		
		request_list_unblock();
		return;
	}
		
	/*
	 * Add this request to the list
	 */
	if (to_replace == NULL) {
		curreq = alloc_entry(sizeof *curreq);
		curreq->next = NULL;
		curreq->child_pid = pthread_self();
		curreq->timestamp = curtime;
		curreq->type = type;
		curreq->data = data;

		if (prevreq == NULL)
			first_request = curreq;
		else
			prevreq->next = curreq;
	} else {
		debug(1, ("replacing request dated %s",
			  ctime(&to_replace->timestamp)));
				
		request_class[to_replace->type].free(to_replace->data);
		curreq = to_replace;
		curreq->timestamp = curtime;
		curreq->type = type;
		curreq->data = data;
	}

	curreq->child_pid = pthread_self();
	
	debug(1, ("%s request %lu added to the list. %d requests held.", 
		  request_class[type].name,
		  (u_long) curreq->child_pid,
		  request_count+1));

	request_list_unblock();

	pthread_cleanup_push(rad_cleanup_thread, curreq);
	/* Finally, handle the request */
	curreq->child_return = request_class[type].handler(data, activefd);
	pthread_cleanup_pop(1);
	log_close();
	return;
}

int
flush_request_list()
{
	REQUEST	*curreq;
	REQUEST	*prevreq;
	UINT4	curtime;
	int	request_count;
	
	curtime = (UINT4)time(NULL);
	request_count = 0;
	curreq = first_request;
	prevreq = NULL;

	/* Block asynchronous access to the list
	 */
	request_list_block();

	while (curreq != NULL) {
		if (curreq->child_pid == 0) {
			/* Request completed, delete it no matter how
			   long does it reside in the queue */
			debug(1, ("deleting completed %s request",
				 request_class[curreq->type].name));
			if (prevreq == NULL) {
				first_request = curreq->next;
				request_free(curreq);
				curreq = first_request;
			} else {
				prevreq->next = curreq->next;
				request_free(curreq);
				curreq = prevreq->next;
			}
		} else if (curreq->timestamp +
			   request_class[curreq->type].ttl <= time(NULL)) {
			/* kill the request */
			radlog(L_NOTICE,
			       _("Killing unresponsive %s child pid %d"),
			       request_class[curreq->type].name,
			       curreq->child_pid);
			pthread_cancel(curreq->child_pid);
			curreq = curreq->next;
		} else {
			prevreq = curreq;
			curreq = curreq->next;
			request_count++;
		}
	}

	request_list_unblock();
	return request_count;
}

int
stat_request_list(stat)
	QUEUE_STAT stat;
{
	int     pending_count[R_MAX] = {0};
	int     completed_count[R_MAX] = {0};
	REQUEST	*curreq;
	int     i;
	
	curreq = first_request;
	/* Block asynchronous access to the list
	 */
	request_list_block();

	while (curreq != NULL) {
		if (curreq->child_pid == 0) 
			completed_count[curreq->type]++;
		else
			pending_count[curreq->type]++;

		curreq = curreq->next;
	}
	request_list_unblock();

	/* Report the results */
	for (i = 0; i < NITEMS(request_class); i++) {
		stat[i][0] = pending_count[i];
		stat[i][1] = completed_count[i];
	}

	return 0;
}

/* ************************************************************************* */
int
radreq_cmp(a, b)
	RADIUS_REQ *a, *b;
{
	return !(a->ipaddr == b->ipaddr &&
		 a->id == b->id &&
			memcmp(a->vector, b->vector, sizeof(a->vector)) == 0);
}

void
rad_req_free(req)
	RADIUS_REQ *req;
{
	if (req->data_alloced)
		efree(req->data);
	radreq_free(req);
}

void
rad_req_drop(type, radreq, status_str)
	int type;
	RADIUS_REQ *radreq;
	char *status_str;
{
	char buf[MAX_LONGNAME];
	
	radlog(L_NOTICE,
	       _("Dropping %s packet from client %s, ID: %d: %s"),
	       request_class[type].name,
	       client_lookup_name(radreq->ipaddr, buf, sizeof buf),
	       radreq->id,
	       status_str);

	switch (type) {
	case R_AUTH:
		stat_inc(auth, radreq->ipaddr, num_dropped);
		break;
	case R_ACCT:
		stat_inc(acct, radreq->ipaddr, num_dropped);
	}
}
/* ************************************************************************* */

/*
 *	Display the syntax for starting this program.
 */
void
usage()
{
	static char ustr[] =
"usage: radiusd [options]\n\n"
"options are:\n"
"    -A, --log-auth-detail       Do detailed authentication logging.\n"
"    -a, --acct-directory DIR    Specify accounting directory.\n"
#ifdef USE_DBM
"    -b, --dbm                   Enable DBM support.\n"
#endif
"    -d, --config-directory DIR  Specify alternate configuration directory\n"
"                                (default " RADIUS_DIR ").\n"
"    -f, --foreground            Stay in foreground.\n"
"    -L, --license               Display GNU license and exit\n"
"    -l, --logging-directory DIR Specify alternate logging directory\n"
"                                (default " RADLOG_DIR ").\n"
"    -m, --mode {t|c|b}          Select operation mode: test, checkconf,\n"
"                                builddbm.\n"
"    -N, --auth-only             Start only authentication process.\n"
"    -n, --do-not-resolve        Do not resolve IP addresses.\n"
"    -i, --ip-address IP         Use this IP as source address.\n"	
"    -p, --port PORTNO           Use alternate port number.\n"
"    -P, --pid-file-dir DIR      Store pidfile in DIR.\n"
"                                (default " RADPID_DIR ")\n"
"    -S, --log-stripped-names    Log usernames stripped off any\n"
"                                prefixes/suffixes.\n"
"    -s, --single-process        Run in single process mode.\n"
"    -v, --version               Display program version and configuration\n"
"                                parameters and exit.\n"
"    -x, --debug debug_level     Set debugging level.\n"
"    -y, --log-auth              Log authentications.\n"
"    -z, --log-auth-pass         Log passwords used.\n"; 
	fprintf(stdout, "%s", ustr);
	fprintf(stdout, "\nReport bugs to <%s>\n", bug_report_address);
	exit(1);
}

/*
 *	Clean up and exit.
 */
void
rad_exit(sig)
	int sig;
{
	static int exiting;

	if (exiting) /* Prevent recursive invocation */
		return ;
	exiting++;

	stat_done();
	unlink_pidfile();

	switch (sig) {
	case 101:
		radlog(L_CRIT, _("failed in select() - exit."));
		break;
	case SIGINT:  /* Foreground mode */
	case SIGTERM:
		radlog(L_CRIT, _("Normal shutdown."));
		break;
	default:
		radlog(L_CRIT, _("exit on signal (%d)"), sig);
		abort();
	}

	rad_sql_shutdown();
	exit(sig == SIGTERM ? 0 : 1);
}

int
rad_flush_queues()
{
	/* Flush request queues */
	radlog(L_NOTICE, _("flushing request queues"));

	while (flush_request_list())
		/*mothing:FIXME*/sleep(1);

	return 0;
}

/* Restart RADIUS process
 */
int
rad_restart()
{
	pid_t pid;
	struct socket_list *slist;
	
	radlog(L_NOTICE, _("restart initiated"));
	if (xargv[0][0] != '/') {
		radlog(L_ERR,
		       _("can't restart: not started as absolute pathname"));
		return -1;
	}
	
	/* Flush request queues */
	rad_flush_queues();
	
	if (foreground)
		pid = 0; /* make-believe we're child */
	else 
		pid = fork();
	
	if (pid < 0) {
		radlog(L_CRIT|L_PERROR,
		       _("rad_restart: cannot fork"));
		return -1;
	}

	/* Close all channels we were listening to */
	for (slist = socket_first; slist; slist = slist->next) 
		close(slist->fd);

	/* Restore signals */
	signal(SIGHUP, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
#if !defined(MAINTAINER_MODE)
	signal(SIGTRAP, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
	signal(SIGILL, SIG_DFL);
#endif
#if 0
	signal(SIGIOT, SIG_DFL);
#endif
	
	if (pid > 0) {
		/* Parent */
		sleep(10);
		exit(0);
	}

	/* Let the things settle */
	sleep(10);

	/* Child */
	radlog(L_NOTICE, _("restarting radius"));
	execvp(xargv[0], xargv);
	radlog(L_CRIT|L_PERROR, _("RADIUS NOT RESTARTED: exec failed"));
	exit(1);
	/*NOTREACHED*/
}


/*
 *	We got a fatal signal. Clean up and exit.
 */
static RETSIGTYPE
sig_fatal(sig)
	int sig;
{
	rad_exit(sig);
}

/*
 *	We got the hangup signal.
 *	Re-read the configuration files.
 */
/*ARGSUSED*/
static RETSIGTYPE
sig_hup(sig)
	int sig;
{
	radlog(L_INFO, _("got HUP. Reloading configuration now"));
	need_reload = 1;
	signal(SIGHUP, sig_hup);
}

int
meminfo_report(stat)
	CLASS_STAT *stat;
{
	radlog(L_INFO,
	       "%9d   %1d    %9d %9d %9d %9d",
	       stat->elsize,
	       stat->cont, 
	       stat->elcnt,
	       stat->bucket_cnt,
	       stat->allocated_cnt,
	       stat->bucket_cnt * stat->elcnt);
	return 0;
}

void
meminfo()
{
	MEM_STAT stat;
	
	mem_get_stat(&stat);

	radlog(L_INFO,
	       _("%lu classes, %lu buckets are using %lu bytes of memory"),
	       stat.class_cnt,
	       stat.bucket_cnt,
	       stat.bytes_allocated);
	
	if (stat.bytes_allocated) 
		radlog(L_INFO,
		       _("memory utilization: %ld.%1ld%%"),
		       stat.bytes_used * 100 / stat.bytes_allocated,
		       (stat.bytes_used * 1000 / stat.bytes_allocated) % 10);

	radlog(L_INFO,
	       _("    Class Cont  Els/Bucket   Buckets   ElsUsed  ElsTotal"));
	
	mem_stat_enumerate(meminfo_report, NULL);

#ifdef LEAK_DETECTOR
	radlog(L_INFO, _("malloc statistics: %d blocks, %d bytes"),
	       mallocstat.count, mallocstat.size);
#endif
}

/*ARGSUSED*/
RETSIGTYPE
sig_usr1(sig)
	int sig;
{
	radlog(L_INFO, _("got USR1. Dumping memory usage statistics"));
	flush_request_list();
	meminfo();
	signal(SIGUSR1, sig_usr1);
}

/*ARGSUSED*/
RETSIGTYPE
sig_dumpdb(sig)
	int sig;
{
	radlog(L_INFO, _("got INT. Dumping users db to `%s'"),
	       RADIUS_DUMPDB_NAME);
	dump_users_db();
	signal(sig, sig_dumpdb);
}

int
open_socket(ipaddr, port, type)
	UINT4 ipaddr;
	int port;
	char *type;
{
	struct	sockaddr	salocal;
	struct	sockaddr_in	*sin;

	int fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		radlog(L_CRIT|L_PERROR, "%s socket", type);
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(ipaddr);
	sin->sin_port = htons(port);

	if (bind (fd, & salocal, sizeof (*sin)) < 0) {
		radlog(L_CRIT|L_PERROR, "%s bind", type);
		exit(1);
	}
	return fd;
}

void
open_socket_list(hostlist, defport, descr, s, r, f)
	HOSTDECL *hostlist;
	int defport;
	char *descr;
	int (*s)();
	int (*r)();
	int (*f)();
{
	int fd;

	if (!hostlist) {
		fd = open_socket(myip, defport, descr);
		add_socket_list(fd, s, r, f);
		return;
	}
	
	for (; hostlist; hostlist = hostlist->next) {
		fd = open_socket(hostlist->ipaddr,
				 hostlist->port > 0 ? hostlist->port : defport,
				 descr);
		add_socket_list(fd, s, r, f);
	}
}

static char buf[128];
int doprompt;

char *
moreinput(buf, bufsize)
	char *buf;
	size_t bufsize;
{
	if (doprompt)
		printf("%% ");
	return fgets(buf, bufsize, stdin);
}

int
test_shell()
{
	char *tok;
	int c;
	NAS *nas;
	struct radutmp ut;
	Datatype type;
	Datum datum;

	printf("** TEST MODE **\n");
	doprompt = isatty(fileno(stdin));
	while (tok = moreinput(buf, sizeof(buf))) {
		int argc;
		char **argv;

                while (*tok && isspace(*tok))
			tok++;
		c = strlen(tok);
		if (c > 1 && tok[c-1] == '\n')
			tok[c-1] = 0;
		c = *tok++;
								
		switch (c) {
		case 0:
		case '#':
			continue;
		case 'h':
		case '?':
			printf("h,?                       help\n");
			printf("q,<EOF>                   quit\n");
			printf("c NAS LOGIN SID PORT [IP] checkrad\n");
			printf("r FUNCALL                 function call\n");
			printf("d LEVEL[,LEVEL]           set debug level\n");
#ifdef USE_SERVER_GUILE
			printf("g                         enter guile shell\n");
#endif
                        printf("m                         display memory usage\n"); 
			break;
		case 'd':
			set_debug_levels(tok);
			break;
#ifdef USE_SERVER_GUILE
                case 'g':
			scheme_read_eval_loop();
			break;
#endif
		case 'q':
			return 0;
		case 'c': /* checkrad */
			if (argcv_get(tok, "", &argc, &argv)) {
				fprintf(stderr, "can't parse input\n");
				argcv_free(argc, argv);
				continue;
			}

			if (argc < 4 || argc > 5) {
				fprintf(stderr, "arg count\n");
				continue;
			}
			nas = nas_lookup_name(argv[0]);
			if (!nas) {
				printf("bad nas\n");
				argcv_free(argc, argv);
				continue;
			}
			ut.nas_address = nas->ipaddr;

			strncpy(ut.orig_login, argv[1], sizeof(ut.orig_login));
			strncpy(ut.session_id, argv[2], sizeof(ut.session_id));
			ut.nas_port = atoi(argv[3]);
			if (argc == 5) 
				ut.framed_address = ip_strtoip(argv[5]);
			argcv_free(argc, argv);
			printf("%d\n", checkrad(nas, &ut));
			break;
		case 'r':
			/* r funcall */
			if (interpret(tok, NULL, &type, &datum))
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
				}
				printf("\n");
			}
			break;
		case 's':
			printf("%d\n", parse_rewrite(tok));
			break;
		case 'm': /*memory statistics */
			meminfo();
			break;
		default:
			printf("no command\n");
		}
	}
	return 0;
}

