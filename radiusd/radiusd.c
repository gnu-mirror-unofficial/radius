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

#define RADIUS_MODULE 2

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
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif
#include <radiusd.h>
#include <radsql.h>
#include <log.h>
#include <symtab.h>

#if defined (sun) && defined(__svr4__)
RETSIGTYPE (*sun_signal(int signo, void (*func)(int)))(int);
#define signal sun_signal
#endif

/* ********************** Request list handling **************************** */
	
typedef struct request {
	struct request *next;      /* Link to the next request */
	int             type;      /* request type */
	time_t          timestamp; /* when was the request accepted */
	pid_t           child_pid; /* PID of the handling process (or -1) */
	void           *data;      /* Request-specific data */
} REQUEST;

void rad_req_free(AUTH_REQ *req);
void rad_req_drop(int type, AUTH_REQ *ptr, char *status_str);
int authreq_cmp(AUTH_REQ *a, AUTH_REQ *b);

struct request_class request_class[] = {
	{ "AUTH", 0, MAX_REQUEST_TIME, CLEANUP_DELAY, 1,
	  rad_authenticate, authreq_cmp, rad_req_free, rad_req_drop,
	  rad_sql_setup, rad_sql_cleanup },
	{ "ACCT", 0, MAX_REQUEST_TIME, CLEANUP_DELAY, 1,
	  rad_accounting,   authreq_cmp, rad_req_free, rad_req_drop,
	  rad_sql_setup, rad_sql_cleanup },
	{ "PROXY",0, MAX_REQUEST_TIME, CLEANUP_DELAY, 0,
	  rad_proxy, authreq_cmp, rad_req_free, rad_req_drop,
	  NULL, NULL },
#ifdef USE_SNMP
	{ "SNMP", 0, MAX_REQUEST_TIME, 0, 1,
	  snmp_answer, snmp_req_cmp, snmp_req_free, snmp_req_drop,
	  NULL, NULL }
#endif
};

/* the request queue */
static REQUEST		*first_request;

/*
 * This flag was used to block the asynchronous access to the request
 * queue. 
 * Now all the list fiddling is done synchronously but I prefere to keep
 * the request_list_[un]block placeholders around. They could be needed
 * when I at last write a multi-threaded version.
 */
#if 0
 static int		request_list_busy = 0;
# define request_list_block()   request_list_busy++
# define request_list_unblock() request_list_busy--
#else
# define request_list_block()
# define request_list_unblock()
#endif

static void request_free(REQUEST *req);
static void request_drop(int type, void *data, char *status_str);
void rad_spawn_child(int type, void *data, int activefd);
static int flush_request_list();
static int request_setup(int type, qid_t qid);
static void request_cleanup(int type, qid_t qid);

/* ************************ Socket control queue ************************** */

struct socket_list {
	struct socket_list *next;
	int fd;
	int (*success)(struct sockaddr *, int);
	int (*respond)(int fd, struct sockaddr *, int, char *, int);
	int (*failure)(struct sockaddr *, int);
};

static struct socket_list *socket_first;
static int max_fd;
static void add_socket_list(int fd, int (*s)(), int (*r)(), int (*f)());
static void rad_select();

/* Implementation functions */
int auth_respond(int fd, struct sockaddr *sa, int salen, char *buf, int size);
int acct_success(struct sockaddr *sa, int salen);
int acct_failure(struct sockaddr *sa, int salen);
int snmp_respond(int fd, struct sockaddr *sa, int salen, char *buf, int size);
int cntl_respond(int fd, struct sockaddr *sa, int salen, char *buf, int size);

/* *************************** Global variables. ************************** */

char			*progname;

int debug_flag; /* can be raised from debugger only */

static int		foreground;
static int		spawn_flag;
int			use_dbm = 0;
int                     open_acct = 1;
int                     auth_detail;
int                     strip_names;

Config config = {
	10,              /* delayed_hup_wait */
	1,               /* checkrad_assume_logged */
	MAX_REQUESTS,    /* maximum number of requests */
	"daemon",        /* exec-program user */
	"daemon",        /* exec-program group */
};

UINT4			myip;
UINT4			warning_seconds;
int			auth_port;
int			acct_port;
int                     cntl_port;
#ifdef USE_SNMP
int                     snmp_port;
#endif


/*
 *	Make sure recv_buffer is aligned properly.
 */
static int		i_recv_buffer[RAD_BUFFER_SIZE];
static u_char		*recv_buffer = (u_char *)i_recv_buffer;

/*
 * The PID of the main process
 */
int		        radius_pid;

/*
 * This flag signals that there is a need to sweep out the dead children,
 * and clean up the request structures associated with them.
 */
static int              need_child_cleanup = 0;
#define schedule_child_cleanup()  need_child_cleanup = 1
#define clear_child_cleanup()     need_child_cleanup = 0

static void rad_child_cleanup();

/*
 * This flag means the reload of the configuration is needed
 */
static int		need_reload = 0;

static void     check_reload();

/*
 * Keeps the timestamp of the last USR2 signal. The need_reload flag gets
 * raised when time(NULL) - delayed_hup_time >= config.delayed_hup_wait.
 * This allows for buffering the configuration requests.
 */
static time_t           delayed_hup_time = 0;


static int	config_init(void);
static void	usage(void);
void   rad_exit(int);
static RETSIGTYPE sig_fatal (int);
static RETSIGTYPE sig_hup (int);
static RETSIGTYPE sig_usr1 (int);
static RETSIGTYPE sig_usr2 (int);
static RETSIGTYPE sig_dumpdb (int);

static int	radrespond (AUTH_REQ *, int);
static int      open_socket(int port, char *type);


static void reread_config(int reload);
static UINT4 getmyip(void);

#define OPTSTR "Aa:bd:cfhl:Lnp:Ssvx:yz"
#ifdef HAVE_GETOPT_LONG
struct option longopt[] = {
	"log-auth-detail",    no_argument,       0, 'A',
	"acct-directory",     required_argument, 0, 'a',
	"check-config",       no_argument,       0, 'c',
#ifdef USE_DBM
	"dbm",                no_argument,       0, 'b',
#endif
	"config-directory",   required_argument, 0, 'd',
	"foreground",         no_argument,       0, 'f',
	"help",               no_argument,       0, 'h', 
	"logging-directory",  no_argument,       0, 'l',
	"license",            no_argument,       0, 'L',
	"auth-only",          no_argument,       0, 'n',
	"port",               required_argument, 0, 'p',
	"log-stripped-names", no_argument,       0, 'S',
	"single-process",     no_argument,       0, 's',
	"version",            no_argument,       0, 'v',
	"debug",              required_argument, 0, 'x',
	"log-auth",           no_argument,       0, 'y',
	"log-auth-pass",      no_argument,       0, 'z',
	0
};
# define GETOPT getopt_long
#else
# define longopt 0
# define GETOPT(ac,av,os,lo,li) getopt(ac,av,os)
#endif

int  xargc;
char **xargv;

int
main(argc, argv)
	int argc;
	char **argv;
{
	struct	servent		*svp;
	int			argval;
	int			t;
	int                     fd;
	int			pid;
	int			radius_port = 0;
	int                     check_config;    
#ifdef RADIUS_PID
	FILE			*fp;
#endif
	
	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	/* debug_flag can be set only from debugger.
	 * It means developer is taking control in his hands, so
	 * we won't modify any variables that could prevent him
	 * from doing so.
	 */
	if (debug_flag == 0) {
		foreground = 0;
		spawn_flag = 1;
	}
	check_config = 0;

	app_setup();

	/* save the invocation */
	xargc = argc;
	xargv = argv;
	
	/*
	 *	Process the options.
	 */
	while ((argval = GETOPT(argc, argv, OPTSTR, longopt, NULL)) != EOF) {
		switch (argval) {
		case 'A':
			auth_detail++;
			break;
		case 'a':
			radacct_dir = optarg;
			break;
#ifdef USE_DBM
		case 'b':
			use_dbm++;
			break;
#endif
		case 'c':
			check_config++;
			break;
		case 'd':
			radius_dir = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'l':
			radlog_dir = optarg;
			break;
		case 'L':
			license();
			exit(0);
		case 'n':
			open_acct = 0;
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

	signal(SIGHUP, sig_hup);
	signal(SIGUSR1, sig_usr1);
	signal(SIGUSR2, sig_usr2);
	signal(SIGQUIT, sig_fatal);
	signal(SIGTERM, sig_fatal);
	signal(SIGCHLD, sig_cleanup);
#if !defined(MAINTAINER_MODE)
	signal(SIGTRAP, sig_fatal);
	signal(SIGFPE, sig_fatal);
	signal(SIGSEGV, sig_fatal);
	signal(SIGILL, sig_fatal);
#endif
#if 0
	signal(SIGIOT, sig_fatal);
#endif

	if (!foreground && !check_config)
		signal(SIGINT, sig_dumpdb);

	for (t = 32; t >= 3; t--)
		close(t);


	/*
	 *	Read config files.
	 */
	get_config();
	stat_init();

	/* 
	 * Determine port numbers for authentication and accounting
	 */
	if (radius_port)
		auth_port = radius_port;
	else {
		svp = getservbyname ("radius", "udp");
		if (svp != (struct servent *) 0)
			auth_port = ntohs(svp->s_port);
		else
			auth_port = PW_AUTH_UDP_PORT;
	}
	svp = getservbyname ("radacct", "udp");
	if (radius_port || svp == (struct servent *) 0)
		acct_port = auth_port + 1;
	else
		acct_port = ntohs(svp->s_port);

	
	reread_config(0);
	if (check_config) 
		exit(0);

	if ((myip = getmyip()) == 0) {
		radlog(L_CRIT, _("can't find out my own IP address"));
		exit(1);
	}

	/*
	 *	Open Authentication socket.
	 */
	fd = open_socket(auth_port, "auth");
	add_socket_list(fd, NULL, auth_respond, NULL);

	if (open_acct) {
		/*
		 *	Open Accounting Socket.
		 */
		fd = open_socket(acct_port, "acct");
		add_socket_list(fd, acct_success, auth_respond, acct_failure);
	}
	
	fd = open_socket(cntl_port, "control");
	if (fd >= 0)
		add_socket_list(fd, NULL, cntl_respond, NULL);
	
#ifdef USE_SNMP

	fd = open_socket(snmp_port, "SNMP");
	set_nonblocking(fd);
	add_socket_list(fd, NULL, snmp_respond, NULL);
	snmp_tree_init();
#endif

	/*
	 *	Disconnect from session
	 */
	if (foreground == 0) {
		pid = fork();
		if (pid < 0) {
			radlog(L_CRIT, _("couldn't fork: %s"), strerror(errno));
			exit(1);
		}
		if (pid > 0) {
			exit(0);
		}
#ifdef HAVE_SETSID
		setsid();
#endif
		chdir("/");
	}
	radius_pid = getpid();
#ifdef RADIUS_PID
	if ((fp = fopen(RADIUS_PID, "w")) != NULL) {
		fprintf(fp, "%d\n", radius_pid);
		fclose(fp);
	}
#endif

	/*
	 *	Use linebuffered or unbuffered stdout if
	 *	the debug flag is on.
	 */
	if (debug_flag)
		setlinebuf(stdout);

	if (!foreground) {
		t = open(RADLOG_DIR "/radius.stderr", O_WRONLY);
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
	}

	radlog(L_INFO, _("Ready to process requests."));

	for(;;) {
		rad_child_cleanup();
		check_reload();
		rad_select();
	}
	/*NOTREACHED*/
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
rad_select()
{
	int                     result;
	int                     status;
	int                     salen;
	struct	sockaddr	saremote;
	fd_set			readfds;
	struct socket_list      *ctl;
	
	FD_ZERO(&readfds);
	for (ctl = socket_first; ctl; ctl = ctl->next) 
		FD_SET(ctl->fd, &readfds);

	status = select(max_fd, &readfds, NULL, NULL, NULL);
	if (status == -1) {
		if (errno == EINTR)
			return;/* give main a chance to do some housekeeping */
		rad_exit(101);
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

int
auth_respond(fd, sa, salen, buf, size)
	int fd;
	struct sockaddr *sa;
	int salen;
	char *buf;
	int size;
{
	AUTH_REQ *authreq;
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	
	authreq = radrecv(ntohl(sin->sin_addr.s_addr),
			  ntohs(sin->sin_port),
			  buf,
			  size);
	radrespond(authreq, fd);
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

int
snmp_respond(fd, sa, salen, buf, size)
	int fd;
	struct sockaddr *sa;
	int salen;
	char *buf;
	int size;
{
	struct snmp_req *req;
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	
	if (req = rad_snmp_respond(buf, size, sin))
		rad_spawn_child(R_SNMP, req, fd);
	return 0;
}

#endif

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
	} else if (pid == radius_pid) {
		radlog(L_INFO, _("Reloading configuration files."));
	}

#ifdef USE_SNMP
	server_stat->auth.status = serv_init;
	server_stat->acct.status = serv_init;
#endif	

	/* Read the options */
	get_config();

	res = reload_config_file(reload_all);

#ifdef USE_SNMP

	server_stat->auth.status = serv_running;
	snmp_auth_server_reset();

	server_stat->acct.status = serv_running;
	snmp_acct_server_reset();
		
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
	char myname[256];

	gethostname(myname, sizeof(myname));
	return get_ipaddr(myname);
}



void
check_reload()
{
	if (delayed_hup_time &&
	    time(NULL) - delayed_hup_time >= config.delayed_hup_wait) {
		delayed_hup_time = 0;
		need_reload = 1;
	}
			
	if (need_reload) {
		reread_config(1);
		need_reload = 0;
	}
#ifdef USE_SNMP
	if (server_stat->auth.status == serv_init ||
	    server_stat->acct.status == serv_init)
		reread_config(1);
#endif		
}	

/*
 *	Respond to supported requests:
 *
 *		PW_AUTHENTICATION_REQUEST - Authentication request from
 *				a client network access server.
 *
 *		PW_ACCOUNTING_REQUEST - Accounting request from
 *				a client network access server.
 *
 *		PW_AUTHENTICATION_ACK
 *		PW_AUTHENTICATION_REJECT
 *		PW_ACCOUNTING_RESPONSE - Reply from a remote Radius server.
 *				Relay reply back to original NAS.
 *
 */
int
radrespond(authreq, activefd)
	AUTH_REQ *authreq;
	int activefd;
{
	int type = -1;
	VALUE_PAIR *namepair;
	int e;


	/*
	 *	First, see if we need to proxy this request.
	 */
	switch (authreq->code) {

	case PW_AUTHENTICATION_REQUEST:
		/*
		 *	Check request against hints and huntgroups.
		 */
		stat_inc(auth, authreq->ipaddr, num_access_req);
		if ((e = rad_auth_init(authreq, activefd)) < 0)
			return e;
		/*FALLTHRU*/
	case PW_ACCOUNTING_REQUEST:
		namepair = pairfind(authreq->request, DA_USER_NAME);
		if (namepair == NULL)
			break;
		if (strchr(namepair->strvalue, '@') &&
		    proxy_send(authreq, activefd) != 0) {
			rad_spawn_child(R_PROXY, authreq, activefd);
			return 0;
		}
		break;

	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_ACCOUNTING_RESPONSE:
		if (proxy_receive(authreq, activefd) < 0) {
			authfree(authreq);
			return 0;
		}
		break;
	}

	/*
	 *	Select the required function and indicate if
	 *	we need to fork off a child to handle it.
	 */
	switch (authreq->code) {

	case PW_AUTHENTICATION_REQUEST:
		rad_sql_check_connect(SQL_AUTH);
		type = R_AUTH;
		break;
	
	case PW_ACCOUNTING_REQUEST:
	case PW_ASCEND_EVENT_REQUEST:
		rad_sql_check_connect(SQL_ACCT);
		type = R_ACCT;
		break;
		
	case PW_PASSWORD_REQUEST:
		/*
		 *	We don't support this anymore.
		 */
		/* rad_passchange(authreq, activefd); */
		radlog(L_NOTICE, "PW_PASSWORD_REQUEST not supported anymore");
		break;

	default:
		stat_inc(acct, authreq->ipaddr, num_unknowntypes);
		radlog(L_NOTICE, _("unknown request %d"), authreq->code); 
		break;
	}

	/*
	 *	If we did select a function, execute it
	 *	(perhaps through rad_spawn_child)
	 */
	if (type != -1) {
	        rad_spawn_child(type, authreq, activefd);
	}
	return 0;
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

int
request_cmp(type, a, b)
	int type;
	void *a, *b;
{
	return request_class[type].comp(a, b);
}

int
request_setup(type, qid)
	int type;
	qid_t qid;
{
	if (request_class[type].setup) 
		return request_class[type].setup(type, qid);
	return 0;
}

void
request_cleanup(type, qid)
	int type;
	qid_t qid;
{
	if (request_class[type].cleanup)
		request_class[type].cleanup(type, qid);
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

/*
 *	Spawns child processes to perform authentication/accounting
 *	and respond to RADIUS clients.  This function also
 *	cleans up complete child requests, and verifies that there
 *	is only one process responding to each request (duplicate
 *	requests are filtered out).
 */
void
rad_spawn_child(type, data, activefd)
	int type;           /* Type of request */
	void *data;         /* Request-specific data */
	int activefd;       /* Active socket descriptor */
{
	REQUEST	*curreq;
	REQUEST	*prevreq;
	UINT4	curtime;
	int	request_count, request_type_count;
	pid_t	child_pid;

	curtime = (UINT4)time(NULL);
	request_count = request_type_count = 0;
	curreq = first_request;
	prevreq = NULL;

	/* Block asynchronous access to the list */
	request_list_block();

	while (curreq != NULL) {
		if (curreq->child_pid == -1 &&
		    curreq->timestamp + 
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
 
		if (curreq->type == type &&
			   request_cmp(type, curreq->data, data) == 0) {
			/*
			 * This is a duplicate request - just drop it
			 */
			request_drop(type, data, _("duplicate request"));
			request_list_unblock();
			schedule_child_cleanup();

			return;
		} else {
			if (curreq->timestamp +
			    request_class[curreq->type].ttl <= curtime &&
			    curreq->child_pid != -1) {
				/*
				 *	This request seems to have hung -
				 *	kill it
				 */
				request_cleanup(curreq->type,
						(qid_t)curreq->data);
				child_pid = curreq->child_pid;
				radlog(L_NOTICE,
				     _("Killing unresponsive %s child pid %d"),
				       request_class[curreq->type].name,
				       child_pid);
				curreq->child_pid = -1;
				curreq->timestamp = curtime -
				     request_class[curreq->type].cleanup_delay;
				kill(child_pid, SIGTERM);
				continue;
			}
			if (curreq->type == type)
				request_type_count++;
			request_count++;
			prevreq = curreq;
			curreq = curreq->next;
		}
	}

	/*
	 *	This is a new request
	 */
	if (request_count >= config.max_requests) {
		request_drop(type, data, _("too many requests in queue"));
		
		request_list_unblock();
		schedule_child_cleanup();
		
		return;
	}
	if (request_class[type].max_requests &&
	    request_type_count >= request_class[type].max_requests) {
		request_drop(type, data, _("too many requests of this type"));

		request_list_unblock();
		schedule_child_cleanup();
		
		return;
	}
	
	/* First, setup the request
	 */
	if (request_setup(type, (qid_t)data)) {
		request_drop(type, data, _("request setup failed"));

		request_list_unblock();
		schedule_child_cleanup();
		
		return;
	}
		
	/*
	 *	Add this request to the list
	 */
	curreq = alloc_entry(sizeof *curreq);
	curreq->next = NULL;
	curreq->child_pid = -1;
	curreq->timestamp = curtime;
	curreq->type = type;
	curreq->data = data;

	if (prevreq == NULL)
		first_request = curreq;
	else
		prevreq->next = curreq;

	debug(1, ("adding %s request to the list. %d requests held.", 
		 request_class[type].name,
		 request_count+1));

	if (spawn_flag == 0 || !request_class[type].spawn) {
		/* 
		 * Execute handler function
		 */
		request_class[type].handler(data, activefd);
		request_cleanup(type, (qid_t)curreq->data);
		request_list_unblock();
		return;
	}

	/*
	 *	fork our child
	 */
	if ((child_pid = fork()) < 0) {
		request_drop(type, data, _("cannot fork"));
		free_entry(curreq);
	}
	if (child_pid == 0) {
		/*
		 *	This is the child, it should go ahead and respond
		 */
		request_list_unblock();
		signal(SIGCHLD, SIG_DFL);
		signal(SIGHUP, SIG_IGN);
		signal(SIGUSR1, SIG_IGN);
		signal(SIGUSR2, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		chdir("/tmp");
		request_class[type].handler(data, activefd);
		exit(0);
	} else {
		debug(1, ("started handler at pid %ld", child_pid));
	}

	/*
	 *	Register the Child
	 */
	curreq->child_pid = child_pid;

	request_list_unblock();
	schedule_child_cleanup();
}

void
rad_child_cleanup()
{
	int		status;
        pid_t		pid;
	REQUEST   	*curreq;
 
	if (!need_child_cleanup)
		return;
	clear_child_cleanup();

        for (;;) {
		pid = waitpid((pid_t)-1, &status, WNOHANG);
                if (pid <= 0)
                        break;

		debug(2, ("child %d died", pid));

#if defined (aix) /* Huh? */
		kill(pid, SIGKILL);
#endif

		curreq = first_request;
		while (curreq != NULL) {
			if (curreq->child_pid == pid) {
				curreq->child_pid = -1;
				/*
				 *	FIXME: UINT4 ?
				 */
				curreq->timestamp = (UINT4)time(NULL);
				request_cleanup(curreq->type,
						(qid_t)curreq->data);
				break;
			}
			curreq = curreq->next;
		}
        }
}

int
flush_request_list()
{
	REQUEST	*curreq;
	REQUEST	*prevreq;
	UINT4	curtime;
	int	request_count;
	pid_t	child_pid;
	
	curtime = (UINT4)time(NULL);
	request_count = 0;
	curreq = first_request;
	prevreq = NULL;

	/* Block asynchronous access to the list
	 */
	request_list_block();

	while (curreq != NULL) {
		if (curreq->child_pid == -1) {
			/*
			 * Request completed, delete it no matter how
			 * long does it reside in the queue  
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
		} else if (curreq->timestamp +
			   request_class[curreq->type].ttl <= time(NULL)) {
			/*
			 *	kill the request
			 */
			child_pid = curreq->child_pid;
			radlog(L_NOTICE,
			       _("Killing unresponsive %s child pid %d"),
			       request_class[curreq->type].name,
			       child_pid);
			curreq->child_pid = -1;
			curreq->timestamp = curtime -
				request_class[curreq->type].cleanup_delay;
			kill(child_pid, SIGTERM);
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
stat_request_list(report)
	int (*report)();
{
	int     pending_count[R_MAX] = {0};
	int     completed_count[R_MAX] = {0};
	REQUEST	*curreq;
	int     i;
	char    tbuf[128];
	
	curreq = first_request;
	/* Block asynchronous access to the list
	 */
	request_list_block();

	while (curreq != NULL) {
		if (curreq->child_pid == -1) 
			completed_count[curreq->type]++;
		else
			pending_count[curreq->type]++;

		curreq = curreq->next;
	}
	request_list_unblock();

	/* Report the results */
	for (i = 0; i < NITEMS(request_class); i++) {
		sprintf(tbuf, "%4.4s  %4d  %4d  %4d",
			request_class[i].name,
			pending_count[i],
			completed_count[i],
			pending_count[i] + completed_count[i]);
		report(tbuf);
	}
	return 0;
}

/* ************************************************************************* */
int
authreq_cmp(a, b)
	AUTH_REQ *a, *b;
{
	return !(a->ipaddr == b->ipaddr &&
		 a->id == b->id &&
			memcmp(a->vector, b->vector, 16) == 0);
}

void
rad_req_free(req)
	AUTH_REQ *req;
{
	if (req->data_alloced)
		efree(req->data);
	authfree(req);
}

void
rad_req_drop(type, authreq, status_str)
	int type;
	AUTH_REQ *authreq;
	char *status_str;
{
	radlog(L_NOTICE,
	       _("Dropping %s packet from client %s, ID: %d: %s"),
	       request_class[type].name,
	       client_name(authreq->ipaddr),
	       authreq->id,
	       status_str);

	switch (type) {
	case R_AUTH:
		stat_inc(auth, authreq->ipaddr, num_dropped);
		break;
	case R_ACCT:
		stat_inc(acct, authreq->ipaddr, num_dropped);
	}
}
/* ************************************************************************* */

#if defined (sun) && defined(__svr4__)
/*
 *	The signal() function in Solaris 2.5.1 sets SA_NODEFER in
 *	sa_flags, which causes grief if signal() is called in the
 *	handler before the cause of the signal has been cleared.
 *	(Infinite recursion).
 */
RETSIGTYPE
(*sun_signal(signo, func))(int)
	int signo;
	void (*func)(int);
{
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
#ifdef  SA_INTERRUPT		/* SunOS */
	act.sa_flags |= SA_INTERRUPT;
#endif
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
}
#endif

/*ARGSUSED*/
RETSIGTYPE
sig_cleanup(sig)
	int sig;
{
	schedule_child_cleanup();
	signal(SIGCHLD, sig_cleanup);
}

/*
 *	Display the syntax for starting this program.
 */
void
usage()
{
	static char ustr[] =
"usage: radiusd [options]\n\n"
"options are:\n"
#ifdef HAVE_GETOPT_LONG
"    -A, --log-auth-detail       Do detailed authentication logging.\n"
"    -a, --acct-directory DIR    Specify accounting directory.\n"
"    -c, --check-config          Do configuration files syntax check\n"
"                                and exit.\n"
#ifdef USE_DBM
"    -b, --dbm                   Enable DBM support. When used twice,\n"
"                                allows to use both `users' file and\n"
"                                DBM database.\n" 
#endif
"    -d, --config-directory DIR  Specify alternate configuration directory\n"
"                                (default " RADIUS_DIR ").\n"
"    -f, --foreground            Stay in foreground.\n"
"    -L, --license               Display GNU license and exit\n"
"    -l, --logging-directory DIR Specify alternate logging directory\n"
"                                (default " RADLOG_DIR ").\n"
"    -n, --auth-only             Start only authentication process.\n"
"    -p, --port PORTNO           Use alternate port number.\n" 
"    -S, --log-stripped-names    Log usernames stripped off any\n"
"                                prefixes/suffixes.\n"
"    -s, --single-process        Run in single process mode.\n"
"    -v, --version               Display program version and exit.\n"
"    -x, --debug debug_level     Set debugging level.\n"
"    -y, --log-auth              Log authentications.\n"
"    -z, --log-auth-pass         Log passwords used.\n"
#else
"    -A                          Do detailed authentication logging.\n"
"    -a DIR                      Specify accounting directory.\n"
"    -c                          Do configuration files syntax check\n"
"                                and exit.\n"
#ifdef USE_DBM
"    -b                          Enable DBM support. When used twice,\n"
"                                allows to use both `users' file and\n"
"                                DBM database.\n" 
#endif
"    -d DIR                      Specify alternate configuration directory\n"
"                                (default " RADIUS_DIR ").\n"
"    -f                          Stay in foreground.\n"
"    -L                          Display GNU license and exit.\n"
"    -l DIR                      Specify alternate logging directory\n"
"                                (default " RADLOG_DIR ").\n"
"    -n                          Start only authentication process.\n"
"    -p PORTNO                   Use alternate port number.\n" 
"    -S                          Log usernames stripped off any\n"
"                                prefixes/suffixes.\n"
"    -s                          Run in single process mode.\n"
"    -v                          Display program version and exit.\n"
"    -x debug_level              Set debugging level.\n"
"    -y                          Log authentications.\n"
"    -z                          Log passwords used.\n"
#endif
;
	fprintf(stdout, "%s", ustr);
	exit(1);
}


/*
 *	Intializes configuration values:
 *
 *		warning_seconds - When acknowledging a user authentication
 *			time remaining for valid password to notify user
 *			of password expiration.
 *
 *	These values are read from the SERVER_CONFIG part of the
 *	dictionary (of all places!)
 */
int
config_init()
{
	DICT_VALUE	*dval;

	if (!(dval = dict_valfind("Password-Warning"))) 
		warning_seconds = (UINT4)0;
	else 
		warning_seconds = dval->value * (UINT4)SECONDS_PER_DAY;

#if 0
	if (!(dval = dict_valfind("Password-Expiration"))) 
		password_expiration = 0;
	else
		passvord_expiration = dval->value * SECONDS_PER_DAY;
#endif
	return 0;
}

/*
 *	Clean up and exit.
 */
void
rad_exit(sig)
	int sig;
{
	char *me = _("MASTER: ");
	static int exiting;

	if (exiting) /* Prevent recursive invocation */
		return ;
	exiting++;
	
	if (radius_pid == getpid()) {
		/*
		 *      FIXME: kill all children.
		 */
		stat_done();
#ifdef RADIUS_PID		
		unlink(RADIUS_PID);
#endif		
	} else {
		me = _("CHILD: ");
	}

	switch (sig) {
	case 101:
		radlog(L_CRIT, _("%sfailed in select() - exit."), me);
		break;
	case SIGTERM:
		radlog(L_CRIT, _("%sNormal shutdown."), me);
		break;
	default:
		radlog(L_CRIT, _("%sexit on signal (%d)"), me, sig);
		break;
	}

	exit(sig == SIGTERM ? 0 : 1);
}

int
rad_flush_queues()
{
	/* Flush request queues */
	radlog(L_NOTICE, _("flushing request queues"));

	while (flush_request_list())
		;

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
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
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
	signal(SIGHUP, sig_hup);
	radlog(L_INFO, _("got HUP. Reloading configuration now"));
	need_reload = 1;
}

int
report_info(s)
	char *s;
{
	radlog(L_INFO, "%s", s);
}

/*ARGSUSED*/
RETSIGTYPE
sig_usr1(sig)
	int sig;
{
	signal(SIGUSR1, sig_usr1);
	radlog(L_INFO, _("got USR1. Dumping memory usage statistics"));
	flush_request_list();
	meminfo(report_info);
#ifdef LEAK_DETECTOR
	radlog(L_INFO, _("malloc statistics: %d blocks, %d bytes"),
	       mallocstat.count, mallocstat.size);
#endif
}

/*ARGSUSED*/
RETSIGTYPE
sig_usr2(sig)
	int sig;
{
	signal(SIGUSR2, sig_usr2);
	radlog(L_INFO, _("got USR2. Reloading configuration in %ld sec."),
	       config.delayed_hup_wait);
	delayed_hup_time = time(NULL);
}

/*ARGSUSED*/
RETSIGTYPE
sig_dumpdb(sig)
	int sig;
{
	signal(sig, sig_dumpdb);
	radlog(L_INFO, _("got INT. Dumping users db to `%s'"),
	       RADIUS_DUMPDB_NAME);
	dump_users_db();
}

int
master_process()
{
	return radius_pid == 0 || getpid() == radius_pid;
}

#if defined(O_NONBLOCK)
# define FCNTL_NONBLOCK O_NONBLOCK
#elif defined(O_NDELAY)
# define FCNTL_NONBLOCK O_NDELAY
#else
# error "Neither O_NONBLOCK nor O_NDELAY are defined"
#endif

int
set_nonblocking(fd)
	int fd;
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		radlog(L_ERR, "F_GETFL: %s", strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | FCNTL_NONBLOCK) < 0) {
		radlog(L_ERR, "F_GETFL: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int
open_socket(port, type)
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
	sin->sin_addr.s_addr = INADDR_ANY;
	sin->sin_port = htons(port);

	if (bind (fd, & salocal, sizeof (*sin)) < 0) {
		radlog(L_CRIT|L_PERROR, "%s bind", type);
		exit(1);
	}
	return fd;
}

