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
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <radiusd.h>
#include <radargp.h>
#include <radsql.h>
#include <symtab.h>
#include <radutmp.h>
#include <rewrite.h>
#ifdef USE_SERVER_GUILE
# include <libguile.h>
#endif
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <argcv.h>
#include <envar.h>

/* ********************** Request list handling **************************** */
        
void rad_req_free(RADIUS_REQ *req);
int rad_req_cmp(RADIUS_REQ *a, RADIUS_REQ *b);
int rad_req_setup(REQUEST *radreq);
void rad_req_xmit(int type, int code, void *data, int fd);

struct request_class request_class[] = {
        { "AUTH", 0, MAX_REQUEST_TIME, CLEANUP_DELAY, 
          rad_req_setup, rad_authenticate, rad_req_xmit, rad_req_cmp,
          rad_req_free, rad_req_drop, rad_sql_cleanup },
        { "ACCT", 0, MAX_REQUEST_TIME, CLEANUP_DELAY,
          rad_req_setup, rad_accounting, rad_req_xmit, rad_req_cmp,
          rad_req_free, rad_req_drop, rad_sql_cleanup },
        { "PROXY",0, MAX_REQUEST_TIME, CLEANUP_DELAY,
          NULL, rad_proxy, rad_req_xmit, rad_req_cmp,
          rad_req_free, proxy_retry, NULL },
#ifdef USE_SNMP
        { "SNMP", 0, MAX_REQUEST_TIME, 0, 
          NULL, snmp_answer, NULL, snmp_req_cmp,
          snmp_req_free, snmp_req_drop, NULL },
#endif
        { NULL, }
};

/* Implementation functions */
int auth_respond(int fd, struct sockaddr *sa, int salen,
                 u_char *buf, int size);
int acct_success(struct sockaddr *sa, int salen);
int acct_failure(struct sockaddr *sa, int salen);
int snmp_respond(int fd, struct sockaddr *sa, int salen,
                 u_char *buf, int size);
int radiusd_respond(int fd, RADIUS_REQ *radreq, u_char *buf, size_t size);

struct request_handler_tab request_handler_tab[] = {
	/* AUTH */  { NULL, auth_respond, NULL },
	/* ACCT */  { acct_success, auth_respond, acct_failure },
	/* PROXY */ { NULL, NULL, NULL },/* not used currently */
#ifdef USE_SNMP
	/* SNMP */  { NULL, snmp_respond, NULL }, 
#endif
};

/* *************************** Global variables. ************************** */

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
                    /* These are the user flag marking attributes that
		       can be used in comparing ... */
int auth_comp_flag; /* ... authentication requests */ 
int acct_comp_flag; /* ... accounting requests */

int checkrad_assume_logged = 1;
int max_requests = MAX_REQUESTS;
char *exec_user = NULL;

UINT4 warning_seconds;
int use_guile;
char *message_text[MSG_COUNT];

UINT4 myip = INADDR_ANY;
int auth_port;
int acct_port;
#ifdef USE_SNMP
int snmp_port;
#endif
SOCKET_LIST *socket_first;

pthread_t radius_tid;       /* Thread ID of the main thread */
pthread_attr_t thread_attr; /* Attribute for creating child threads */

int max_threads = 128;  /* Maximum number of threads allowed */
int num_threads = 0;    /* Number of threads currently spawned */

#define CMD_NONE     0 /* No command */
#define CMD_RELOAD   1 /* The reload of the configuration is needed */
#define CMD_RESTART  2 /* Try to restart ourselves when set to 1 */
#define CMD_MEMINFO  3 /* Dump memory usage statistics */
#define CMD_DUMPDB   4 /* Dump authentication database */
#define CMD_SHUTDOWN 5 /* Stop immediately */

int daemon_command = CMD_NONE;

static void check_reload();
static void check_snmp_request();

static void set_config_defaults();
void radiusd_exit();
static int sig_exit (int, void *, rad_sigid_t, const void *);
static int sig_fatal (int, void *, rad_sigid_t, const void *);
static int sig_hup (int, void *, rad_sigid_t, const void *);
static int sig_dumpdb (int, void *, rad_sigid_t, const void *);

static struct signal_list {
	int mask;  /* 1 if the signal should be masked in the threads */
	int sig;
	int type;
	rad_signal_t handler;
} rad_signal_list[] = {
        1, SIGHUP,  SH_ASYNC, sig_hup,
        0, SIGQUIT, SH_ASYNC, sig_exit,
        0, SIGTERM, SH_ASYNC, sig_exit,
	0, SIGCHLD, SH_ASYNC, NULL,
        0, SIGBUS,  SH_ASYNC, sig_fatal,
        0, SIGTRAP, SH_ASYNC, sig_fatal,
        0, SIGFPE,  SH_ASYNC, sig_fatal,
        0, SIGSEGV, SH_ASYNC, sig_fatal,
        0, SIGILL,  SH_ASYNC, sig_fatal,
        1, SIGINT,  SH_ASYNC, sig_dumpdb
};

sigset_t rad_signal_set;

static int rad_cfg_listen_auth(int argc, cfg_value_t *argv,
			       void *block_data, void *handler_data);
static int rad_cfg_listen_acct(int argc, cfg_value_t *argv,
			       void *block_data, void *handler_data);

static void reconfigure();
static void radiusd_daemon();
static void radiusd_watcher();
static void common_init();
static void radiusd_main_loop();
static void radiusd_fork_child_handler();
static void meminfo();
static void radiusd_before_config_hook(void *unused1, void *unused2);
static void radiusd_after_config_hook(void *unused1, void *unused2);

int radius_mode = MODE_DAEMON;    
int radius_port = 0;

int  xargc;
char **xargv;
char *x_debug_spec;

extern void version(FILE *stream, struct argp_state *state);

const char *argp_program_version = "radiusd (" PACKAGE ") " VERSION;
static char doc[] = N_("GNU radius daemon");

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         N_("radiusd specific switches:"), 0},
        {"log-auth-detail", 'A', 0, 0,
         N_("Do detailed authentication logging"), 0},
        {"acct-directory",  'a', N_("DIR"), 0,
         N_("Set accounting directory"), 0},
#ifdef USE_DBM
        {"dbm", 'b', NULL, 0,
         N_("Enable DBM support"), 0},
#endif
        {"foreground", 'f', NULL, 0,
         N_("Stay in foreground"), 0},
        {"logging-directory", 'l', N_("DIR"), 0, 
         N_("Set logging directory name"), 0},
        {"mode", 'm', "{t|c|b}", 0,
         N_("Select operation mode: test, checkconf, builddbm.")},
        {"auth-only", 'N', NULL, 0,
         N_("Do only authentication"), 0},
        {"do-not-resolve", 'n', NULL, 0,
         N_("Do not resolve IP addresses"), 0},
        {"ip-address", 'i', N_("IPADDR"), 0,
         N_("Listen on IPADDR"), 0},
        {"port", 'p', "NUMBER", 0,
         N_("Set authentication port number"), 0},
        {"pid-file-dir", 'P', N_("DIR"), 0,
         N_("Store pidfile in DIR"), 0},
        {"log-stripped-names", 'S', NULL, 0,
         N_("Strip prefixes/suffixes off user names before logging")},
        {"single-process", 's', NULL, 0,
         N_("Run in single process mode"), 0},
        {"debug", 'x', N_("DEBUGSPEC"), 0,
         N_("Set debugging level"), 0},
        {"log-auth", 'y', NULL, 0,
         N_("Log authentications"), 0},
        {"log-auth-pass", 'z', NULL, 0,
         N_("Log users' passwords"), 0},
        {NULL, 0, NULL, 0, NULL, 0}
};
        
/*ARGSUSED*/
static error_t
parse_opt (key, arg, state)
        int key;
        char *arg;
        struct argp_state *state;
{
        switch (key) {
        case 'A':
                auth_detail++;
                break;
        case 'a':
                radacct_dir = string_create(optarg);
                break;
#ifdef USE_DBM
        case 'b':
                use_dbm++;
                break;
#endif
        case 'f':
                foreground = 1;
                break;
        case 'l':
                radlog_dir = string_create(optarg);
                break;
        case 'm':
                switch (arg[0]) {
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
                               _("unknown mode: %s"), arg);
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
        case 's':       /* Single process mode */
                spawn_flag = 0;
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
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static struct argp argp = {
        options,
        parse_opt,
        NULL,
        doc,
        rad_common_argp_child,
        NULL, NULL
};

int
main(argc, argv)
        int argc;
        char **argv;
{
        struct servent *svp;
        int t;
	char *p;
	FILE *fp;
	pid_t pid;

        for (t = getmaxfd(); t >= 3; t--)
                close(t);

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

        /* Process the options.  */
        argp_program_version_hook = version;
        if (rad_argp_parse(&argp, &argc, &argv, 0, NULL, NULL))
                return 1;

        log_set_default("default.log", -1, -1);
        if (radius_mode != MODE_DAEMON)
                log_set_to_console();
        
        /* Determine default port numbers for authentication and accounting */
        if (radius_port)
                auth_port = radius_port;
        else {
                svp = getservbyname ("radius", "udp");
                if (svp)
                        auth_port = ntohs(svp->s_port);
                else
                        auth_port = DEF_AUTH_PORT;
        }
        if (radius_port || (svp = getservbyname ("radacct", "udp")) == NULL)
                acct_port = auth_port + 1;
        else
                acct_port = ntohs(svp->s_port);

        srand(time(NULL));
        
	/* Register radiusd hooks first. This ensures they will be
	   executed after all other hooks */
	register_before_config_hook(radiusd_before_config_hook, NULL);
	register_after_config_hook(radiusd_after_config_hook, NULL);

        snmp_init(0, 0, (snmp_alloc_t)emalloc, (snmp_free_t)efree);
#ifdef USE_SNMP
        snmpserv_init(&saved_status);
#endif

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
		chdir("/");
		umask(022);

                if (!foreground)
                        radiusd_daemon();
		
                common_init();
        }

	radiusd_pidfile_write(RADIUSD_PID_FILE);

        radiusd_main_loop();
	/*NOTREACHED*/
}

void
set_config_defaults()
{
        exec_user  = string_create("daemon");
        username_valid_chars = string_create(".-_!@#$%^&\\/");
        message_text[MSG_ACCOUNT_CLOSED] =
                string_create(_("Sorry, your account is currently closed\n"));
        message_text[MSG_PASSWORD_EXPIRED] =
                string_create(_("Password has expired\n"));
        message_text[MSG_PASSWORD_EXPIRE_WARNING] =
                string_create(_("Password will expire in %R{Password-Expire-Days} Days\n"));
        message_text[MSG_ACCESS_DENIED] =
                string_create(_("\nAccess denied\n"));
        message_text[MSG_REALM_QUOTA] =
                string_create(_("\nRealm quota exceeded - access denied\n"));
        message_text[MSG_MULTIPLE_LOGIN] =
                string_create(_("\nYou are already logged in %R{Simultaneous-Use} times - access denied\n"));
        message_text[MSG_SECOND_LOGIN] =
                string_create(_("\nYou are already logged in - access denied\n"));
        message_text[MSG_TIMESPAN_VIOLATION] =
                string_create(_("You are calling outside your allowed timespan\n"));
}

void
radiusd_daemon()
{
        FILE *fp;
        char *p;
        int i;
        pid_t pid;
        
        switch (pid = fork()) {
        case -1:
                radlog(L_CRIT|L_PERROR, "fork");
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
        install_signal(SIGHUP, SIG_IGN);

        /* fork() again so the parent, can exit. This means that we, as a
           non-session group leader, can never regain a controlling
           terminal. */
        switch (pid = fork()) {
        case 0:
                break;
        case -1:
                radlog(L_CRIT|L_PERROR, "fork");
                exit(1);
        default:
                exit(0);
        }

        /* FIXME: This is needed for messages generated by guile
           functions. */
        p = mkfilename(radlog_dir, "radius.stderr");
        i = open(p, O_CREAT|O_WRONLY, 0644);
        if (i != -1) {
                if (i != 2) 
                        dup2(i, 2);
                if (i != 1) 
                        dup2(i, 1);
                if (i != 1 && i != 2)
                        close(i);
                fflush(stdout);
                fflush(stderr);
        }
        efree(p);
}

void
common_init()
{
	int i;
	
	radlog(L_INFO, _("Starting"));

#ifdef HAVE_SETVBUF
        setvbuf(stdout, NULL, _IOLBF, 0);
#endif
        radius_tid = pthread_self();
        pthread_attr_init(&thread_attr);
        pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#ifdef HAVE_PTHREAD_ATFORK
	pthread_atfork(NULL, NULL, radiusd_fork_child_handler);
#endif

        /* Install signal handlers */
	install_signal(SIGPIPE, SIG_IGN);
        install_signal(SIGIOT, SIG_DFL);

	sigemptyset(&rad_signal_set);
	for (i = 0; i < NITEMS(rad_signal_list); i++) {
		rad_signal_install (rad_signal_list[i].sig,
		                    rad_signal_list[i].type,
				    rad_signal_list[i].handler, NULL);
		if (rad_signal_list[i].mask)
			sigaddset(&rad_signal_set, rad_signal_list[i].sig);
	}
        
#ifdef USE_SERVER_GUILE
        start_guile();
#endif
        reconfigure();
	if (x_debug_spec)
		set_debug_levels(x_debug_spec);
	radpath_init();
	stat_init();
	radlog(L_INFO, _("Ready"));
}       

void
radiusd_thread_init()
{
        pthread_sigmask(SIG_SETMASK, &rad_signal_set, NULL);
}

void
radiusd_main_loop()
{
        radlog(L_INFO, _("Ready to process requests."));

        for(;;) {
                struct timeval tv;

		rad_signal_deliver ();
                check_reload();
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                socket_list_select(socket_first,
				   request_handler_tab,
				   NITEMS(request_handler_tab),
				   &tv);
        }
        /*NOTREACHED*/
}


/* ************************************************************************* */
/* Test shell */
   
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

/* ************************************************************************* */

/* Called in the child process just before fork() returns. */
void
radiusd_fork_child_handler()
{
        socket_list_close(&socket_first);
}

void
radiusd_suspend()
{
        suspend_flag = 1;
}

void
radiusd_continue()
{
        suspend_flag = 0;
#ifdef USE_SNMP
        server_stat.auth.status = serv_running;
        server_stat.acct.status = serv_running;
#endif  
}

void
radiusd_schedule_restart()
{
        daemon_command = CMD_RESTART;
}

/* Clean up and exit. */
void
radiusd_exit()
{
        stat_done();
	radiusd_pidfile_remove(RADIUSD_PID_FILE);

	radiusd_flush_queues();
	radlog(L_CRIT, _("Normal shutdown."));

#ifdef USE_SQL
        radiusd_sql_shutdown();
#endif
        exit(0);
}

void
radiusd_abort()
{
        stat_done();
	radiusd_pidfile_remove(RADIUSD_PID_FILE);
	exit(1);
}

int
radiusd_flush_queues()
{
        /* Flush request queues */
        radlog(L_NOTICE, _("flushing request queues"));

        while (request_flush_list())
                /*nothing:FIXME*/sleep(1);

        return 0;
}

/* Restart RADIUS process
 */
int
radiusd_restart()
{
	radlog(L_NOTICE, _("restart initiated"));
        if (xargv[0][0] != '/') {
                radlog(L_ERR,
                       _("can't restart: not started as absolute pathname"));
                return -1;
        }
        
        /* Flush request queues */
        radiusd_flush_queues();
#ifdef USE_SQL
        radiusd_sql_shutdown();
#endif
	return radiusd_primitive_restart(0);
}

int
radiusd_primitive_restart(cont)
	int cont;
{
	int i;
        pid_t pid;
        
        if (foreground)
                pid = 0; /* make-believe we're child */
        else 
                pid = fork();
        
        if (pid < 0) {
                radlog(L_CRIT|L_PERROR, "fork");
                return -1;
        }

        /* Close all channels we were listening to */
        socket_list_close(&socket_first);

        if (pid > 0) {
                /* Parent */
		if (!cont) {
			sleep(10);
			exit(0);
		}
		return 0;
        }

        /* Restore signals */
	for (i = 0; i < NITEMS(rad_signal_list); i++) 
		install_signal(rad_signal_list[i].sig, SIG_DFL);
        
        /* Let the things settle */
        sleep(10);

        /* Child */
        radlog(L_NOTICE, _("restarting radius"));
        execvp(xargv[0], xargv);
        radlog(L_CRIT|L_PERROR, _("RADIUS NOT RESTARTED: exec failed"));
        exit(1);
        /*NOTREACHED*/
}

static int _opened_auth_sockets;
int
auth_stmt_begin(finish, block_data, handler_data)
	int finish;
	void *block_data;
	void *handler_data;
{
	if (!finish) 
		_opened_auth_sockets = 0;
	else if (radius_mode == MODE_DAEMON && !_opened_auth_sockets) 
		socket_list_add(&socket_first,
				R_AUTH,
				INADDR_ANY, auth_port);
	return 0;
}

/* Open authentication sockets. */
int
rad_cfg_listen_auth(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	int i, errcnt = 0;
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON)
		for (i = 1; i < argc; i++) 
			socket_list_add(&socket_first,
					R_AUTH,
					argv[i].v.host.ipaddr,
					argv[i].v.host.port > 0 ?
					argv[i].v.host.port : auth_port);
	_opened_auth_sockets++;
	return 0;
}

static int _opened_acct_sockets;
int
acct_stmt_begin(finish, block_data, handler_data)
	int finish;
	void *block_data;
	void *handler_data;
{
	if (!finish) 
		_opened_acct_sockets = 0;
	else if (radius_mode == MODE_DAEMON && !_opened_acct_sockets)
		socket_list_add(&socket_first,
				R_ACCT,
				INADDR_ANY, acct_port);
	return 0;
}

/* Open accounting sockets. */
int
rad_cfg_listen_acct(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	int i, errcnt = 0;
	
	for (i = 1; i < argc; i++) 
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && open_acct && radius_mode == MODE_DAEMON)
		for (i = 1; i < argc; i++) 
			socket_list_add(&socket_first,
					R_ACCT,
					argv[i].v.host.ipaddr,
					argv[i].v.host.port > 0 ?
					argv[i].v.host.port : acct_port);
	_opened_acct_sockets++;
	return 0;
}

struct cfg_stmt option_stmt[] = {
	{ "source-ip", CS_STMT, NULL, cfg_get_ipaddr, &myip,
	  NULL, NULL },
	{ "max-requests", CS_STMT, NULL, cfg_get_integer, &max_requests,
	  NULL, NULL },
	{ "max-threads", CS_STMT, NULL, cfg_get_integer, &max_threads,
	  NULL, NULL },
	{ "exec-program-user", CS_STMT, NULL, cfg_get_string, &exec_user,
	  NULL, NULL },
	{ "log-dir", CS_STMT, NULL, cfg_get_string, &radlog_dir,
	  NULL, NULL },
	{ "acct-dir", CS_STMT, NULL, cfg_get_string, &radacct_dir,
	  NULL, NULL },
	{ "resolve", CS_STMT, NULL, cfg_get_boolean, &resolve_hostnames,
	  NULL, NULL },
	{ "username-chars", CS_STMT, NULL, cfg_get_string,
	  &username_valid_chars,
	  NULL, NULL },
	{ NULL, }
};

struct cfg_stmt message_stmt[] = {
	{ "account-closed", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_ACCOUNT_CLOSED],
	  NULL, NULL },
	{ "password-expired", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_PASSWORD_EXPIRED],
	  NULL, NULL },
	{ "access-denied", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_ACCESS_DENIED],
	  NULL, NULL },
	{ "realm-quota", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_REALM_QUOTA],
	  NULL, NULL },
	{ "multiple-login", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_MULTIPLE_LOGIN],
	  NULL, NULL },
	{ "second-login", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_SECOND_LOGIN],
	  NULL, NULL },
	{ "timespan-violation", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_TIMESPAN_VIOLATION],
	  NULL, NULL },
	{ "password-expire-warning", CS_STMT, NULL,
	  cfg_get_string, &message_text[MSG_PASSWORD_EXPIRE_WARNING],
	  NULL, NULL },
	{ NULL, }
};

struct cfg_stmt auth_stmt[] = {
	{ "port", CS_STMT, NULL, cfg_get_port, &auth_port, NULL, NULL },
	{ "listen", CS_STMT, NULL, rad_cfg_listen_auth, NULL, NULL, NULL },
	{ "max-requests", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].max_requests, NULL, NULL },
	{ "time-to-live", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].ttl, NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].cleanup_delay, NULL, NULL },
	{ "detail", CS_STMT, NULL, cfg_get_boolean, &auth_detail,
	  NULL, NULL },
	{ "strip-names", CS_STMT, NULL, cfg_get_boolean, &strip_names,
	  NULL, NULL },
	{ "checkrad-assume-logged", CS_STMT, NULL,
	  cfg_get_boolean, &checkrad_assume_logged,
	  NULL, NULL },
	{ "password-expire-warning", CS_STMT, NULL,
	  cfg_get_integer, &warning_seconds,
	  NULL, NULL },
	{ "compare-attribute-flag", CS_STMT, NULL,
	  cfg_get_integer, &auth_comp_flag,
	  NULL, NULL },
	{ NULL, }
};
	
struct cfg_stmt acct_stmt[] = {
	{ "port", CS_STMT, NULL, cfg_get_port, &acct_port, NULL, NULL },
	{ "listen", CS_STMT, NULL, rad_cfg_listen_acct, NULL, NULL, NULL },
	{ "max-requests", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_ACCT].max_requests,
	  NULL, NULL },
	{ "time-to-live", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_ACCT].ttl,
	  NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_ACCT].cleanup_delay,
	  NULL, NULL },
	{ "detail", CS_STMT, NULL, cfg_get_boolean, &acct_detail,
	  NULL, NULL },
	{ "compare-attribute-flag", CS_STMT, NULL,
	  cfg_get_integer, &acct_comp_flag,
	  NULL, NULL },
	{ NULL, }
};

struct cfg_stmt proxy_stmt[] = {
	{ "max-requests", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_PROXY].max_requests,
	  NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_PROXY].cleanup_delay,
	  NULL, NULL },
	{ NULL, }
};

struct cfg_stmt config_syntax[] = {
	{ "option", CS_BLOCK, NULL, NULL, NULL, option_stmt, NULL },
	{ "message", CS_BLOCK, NULL, NULL, NULL, message_stmt, NULL },
	{ "logging", CS_BLOCK, logging_stmt_begin, logging_stmt_handler, NULL,
	  logging_stmt, logging_stmt_end },
	{ "auth", CS_BLOCK, auth_stmt_begin, NULL, NULL, auth_stmt, NULL },
	{ "acct", CS_BLOCK, acct_stmt_begin, NULL, NULL, acct_stmt, NULL  },
	{ "proxy", CS_BLOCK, NULL, NULL, NULL, proxy_stmt, NULL  },
	{ "rewrite", CS_BLOCK, NULL, NULL, NULL, rewrite_stmt, NULL },
	{ "filters", CS_BLOCK, filters_stmt_term, NULL, NULL, filters_stmt,
	  NULL },
#ifdef USE_DBM
	{ "usedbm", CS_STMT, NULL, cfg_get_boolean, &use_dbm, NULL, NULL },
#endif
#ifdef USE_SNMP
	{ "snmp", CS_BLOCK, snmp_stmt_begin, NULL, NULL, snmp_stmt, NULL },
#endif
#ifdef USE_SERVER_GUILE
	{ "guile", CS_BLOCK, NULL, guile_cfg_handler, NULL, guile_stmt, NULL },
#endif
	{ NULL, },
};	

/* ************************************************************************* */

struct config_hook_list {
	struct config_hook_list *next;
	config_hook_fp fun;
	void *data;
};

static struct config_hook_list *before_list;
static struct config_hook_list *after_list;

static void run_config_hooks(struct config_hook_list *list,
			     void *data);
static void register_config_hook(struct config_hook_list **list,
				 config_hook_fp fp, void *data);


void
register_config_hook(listp, fp, data)
	struct config_hook_list **listp;
	config_hook_fp fp;
	void *data;
{
	struct config_hook_list *p = emalloc(sizeof(*p));
	p->fun = fp;
	p->data = data;
	p->next = *listp;
	*listp = p;
}

void
run_config_hooks(list, data)
	struct config_hook_list *list;
	void *data;
{
	for (; list; list = list->next) 
		list->fun(list->data, data);
}

void
run_before_config_hooks(data)
	void *data;
{
	run_config_hooks(before_list, data);
}

void
run_after_config_hooks(data)
	void *data;
{
	run_config_hooks(after_list, data);
}

void
register_before_config_hook(fp, data)
	config_hook_fp fp;
	void *data;
{
	register_config_hook(&before_list, fp, data);
}

void
register_after_config_hook(fp, data)
	config_hook_fp fp;
	void *data;
{
	register_config_hook(&after_list, fp, data);
}

/* ************************************************************************* */

void
socket_after_reconfig(type, fd)
	int type;
	int fd;
{
#ifdef USE_SNMP
	if (type == R_SNMP)
		set_nonblocking(fd);
#endif
}

void
radiusd_before_config_hook(unused1, unused2)
	void *unused1;
	void *unused2;
{
	radiusd_flush_queues();
	socket_list_init(socket_first);
}

void
radiusd_after_config_hook(unused1, unused2)
	void *unused1;
	void *unused2;
{
	if (radius_mode == MODE_DAEMON) {
		if (socket_list_open(&socket_first) == 0) {
			radlog(L_ALERT,
			       _("Radiusd is not listening on any port. Trying to continue anyway..."));
		}
		socket_list_iterate(socket_first, socket_after_reconfig);
	}
}

void
reconfigure()
{
        int res = 0;
        char *filename;
	
	radlog(L_INFO, _("Loading configuration files."));

	run_before_config_hooks(NULL);

        /* Read the options */
        filename = mkfilename(radius_dir, RADIUS_CONFIG);
        cfg_read(filename, config_syntax, NULL);
	efree(filename);

        res = reload_config_file(reload_all);
        
        if (res != 0) {
                radlog(L_CRIT,
                       _("Errors reading config file - EXITING"));
                exit(1);
        }

	run_after_config_hooks(NULL);
}

void
check_reload()
{
        switch (daemon_command) {
        case CMD_RELOAD:
                radlog(L_INFO, _("Reloading configuration now"));
                reconfigure();
                break;
		
        case CMD_RESTART:
                radiusd_restart();
                break;
		
        case CMD_MEMINFO:
                meminfo();
                break;
		
        case CMD_DUMPDB:
                radlog(L_INFO, _("Dumping users db to `%s'"),
		       RADIUS_DUMPDB_NAME);
                dump_users_db();
                break;
		
	case CMD_SHUTDOWN:
		radiusd_exit();
		
        default:
                check_snmp_request();
                break;
        }
        daemon_command = CMD_NONE;
}

void
check_snmp_request()
{
#ifdef USE_SNMP
        if (server_stat.auth.status != saved_status) {
                switch (server_stat.auth.status) {
                case serv_reset: /* Hard reset */
                        if (xargv[0][0] != '/') {
                                radlog(L_NOTICE,
                                       _("can't restart: radiusd not started as absolute pathname"));
                                break;
                        }
                        radiusd_restart();
                        break;
                        
                case serv_init:
                        reconfigure();
                        break;
                        
                case serv_running:
                        if (suspend_flag) {
                                suspend_flag = 0;
                                radlog(L_NOTICE, _("RADIUSD RUNNING"));
                                radiusd_continue();
                        }
                        break;
                        
                case serv_suspended:
                        if (!suspend_flag) {
                                radlog(L_NOTICE, _("RADIUSD SUSPENDED"));
                                radiusd_suspend();
                        }
                        break;
                        
                case serv_shutdown:
                        radiusd_exit();
                        break;
                }
                saved_status = server_stat.auth.status;
        }
#endif
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
               _("%u classes, %u buckets are using %u bytes of memory"),
               stat.class_cnt,
               stat.bucket_cnt,
               stat.bytes_allocated);
        
        if (stat.bytes_allocated) 
                radlog(L_INFO,
                       _("memory utilization: %u.%1u%%"),
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

/* ************************************************************************* */
/* Signal handling */

static int
sig_fatal(sig, data, id, owner)
        int sig;
	void *data;
	rad_sigid_t id;
	const void *owner;
{
	radlog(L_CRIT, _("exit on signal %d"), sig);
	abort();
	return 0;
}

static int
sig_exit(sig, data, id, owner)
        int sig;
	void *data;
	rad_sigid_t id;
	const void *owner;
{
	daemon_command = CMD_SHUTDOWN;
	return 0;
}

/*ARGSUSED*/
static int
sig_hup(sig, data, id, owner)
        int sig;
	void *data;
	rad_sigid_t id;
	const void *owner;
{
        daemon_command = CMD_RELOAD;
	return 0;
}

/*ARGSUSED*/
static int
sig_dumpdb(sig, data, id, owner)
        int sig;
	void *data;
	rad_sigid_t id;
	const void *owner;
{
        daemon_command = CMD_DUMPDB;
        return 0;
}

/* ************************************************************************* */
/* RADIUS request handling functions */

VALUE_PAIR *
rad_req_recode(req, prop)
	RADIUS_REQ *req;
	int prop;
{
	static int attrlist[] = { DA_USER_PASSWORD, DA_CHAP_PASSWORD };
	int i;
	VALUE_PAIR *newlist = NULL;
	VALUE_PAIR *pair;
	char password[AUTH_STRING_LEN+1];

	for (pair = req->request; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(attrlist); i++) {
			if (pair->attribute == attrlist[i]
			    && (pair->prop & prop))
				break;
		}

	if (!pair)
		return NULL;

	newlist = avl_dup(req->request);
	for (pair = newlist; pair; pair = pair->next) 
		for (i = 0; i < NITEMS(attrlist); i++) {
			if (pair->attribute == attrlist[i]
			    && (pair->prop & prop)) {
				req_decrypt_password(password, req, pair);
				string_free(pair->avp_strvalue);
				pair->avp_strvalue = string_create(password);
				pair->avp_strlength = strlen(pair->avp_strvalue);
			}
		}
	return newlist;
}

int
rad_req_cmp(a, b)
        RADIUS_REQ *a, *b;
{
	int prop = 0;
	VALUE_PAIR *alist = NULL, *blist = NULL, *ap, *bp;
	int rc;
	NAS *nas;
	
	if (a->ipaddr != b->ipaddr || a->code != b->code)
		return 1;
	
	if (a->id == b->id
	    && memcmp(a->vector, b->vector, sizeof(a->vector)) == 0)
		return 0;

	if (nas = nas_request_to_nas(a))
		prop = envar_lookup_int(nas->args, "compare-atribute-flag", 0);

	if (!prop) {
		switch (a->code) {
		case RT_AUTHENTICATION_REQUEST:
		case RT_AUTHENTICATION_ACK:
		case RT_AUTHENTICATION_REJECT:
		case RT_ACCESS_CHALLENGE:
			prop = auth_comp_flag;
			break;
		case RT_ACCOUNTING_REQUEST:
		case RT_ACCOUNTING_RESPONSE:
		case RT_ACCOUNTING_STATUS:
		case RT_ACCOUNTING_MESSAGE:
			prop = acct_comp_flag;
			break;
		}
	}

	if (prop == 0) 
		return 1;

	prop |= AP_REQ_CMP;
	alist = rad_req_recode(a, prop);
	blist = rad_req_recode(b, prop);

	ap = alist ? alist : a->request;
	bp = blist ? blist : b->request;
	
	rc = avl_cmp(ap, bp, prop) || avl_cmp(bp, ap, prop);

	avl_free(alist);
	avl_free(blist);
	return rc;
}

void
rad_req_free(req)
        RADIUS_REQ *req;
{
        debug(1,("enter: %p",req));
        if (req->data_alloced)
                efree(req->data);
        radreq_free(req);
        debug(1,("exit"));
}

/*ARGSUSED*/
void
rad_req_drop(type, radreq, origreq, fd, status_str)
        int type;
        RADIUS_REQ *radreq, *origreq;
	int fd;
        char *status_str; 
{
        char buf[MAX_LONGNAME];

	if (!radreq)
		radreq = origreq;
	
        radlog_req(L_NOTICE, radreq,
		   "%s: %s", _("Dropping packet"),  status_str);

        switch (type) {
        case R_AUTH:
                stat_inc(auth, radreq->ipaddr, num_dropped);
                break;
        case R_ACCT:
                stat_inc(acct, radreq->ipaddr, num_dropped);
        }
}

/*ARGSUSED*/
void
rad_req_xmit(type, code, data, fd)
        int type;
        int code;
        void *data;
        int fd;
{
        RADIUS_REQ *req = (RADIUS_REQ*)data;

        if (code == 0) {
                rad_send_reply(0, req, NULL, NULL, fd);
                radlog_req(L_NOTICE, req, _("Retransmitting %s reply"),
                            request_class[type].name);
        } else {
		/* We are here if the handling thread of the request
		   had been cancelled while processing it. */
                rad_req_drop(type, NULL, req, fd, _("request failed"));
        }
}

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
        
        radreq = rad_decode_pdu(ntohl(sin->sin_addr.s_addr),
				ntohs(sin->sin_port),
				buf,
				size);
        if (radiusd_respond(fd, radreq, buf, size)) 
                radreq_free(radreq);

        return 0;
}

/*ARGSUSED*/
int
acct_success(sa, salen)
        struct sockaddr *sa;
        int salen;
{
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        stat_inc(acct, ntohl(sin->sin_addr.s_addr), num_req);
        return 0;
}

/*ARGSUSED*/
int
acct_failure(sa, salen)
        struct sockaddr *sa;
        int salen;
{
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        stat_inc(acct, ntohl(sin->sin_addr.s_addr), num_bad_req);
        return 0;
}

int
rad_request_handle(type, data, fd)
        int type;
        void *data;
        int fd;
{
        int num_active;
        REQUEST *req = request_put(type, data, fd, &num_active);
        if (!req) 
                return -1;

        if (spawn_flag) {
                if (num_active == num_threads) {
                        if (num_threads == max_threads) {
                                radlog(L_NOTICE,
                                       "Maximum number of threads active");
                        } else
                                request_start_thread();
                        return 0;
                }
                debug(100,("Signalling"));
                request_signal();
                debug(100,("SIGNALLED"));
        } else 
                request_handle(req);
        return 0;
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
radiusd_respond(activefd, radreq, buf, size)
        int activefd;
        RADIUS_REQ *radreq;
	u_char *buf;
	size_t size;
{
        int type;
        
        if (suspend_flag)
                return 1;
        
        if (validate_client(radreq)) {
                /*FIXME: update stats */
                return -1;
        }

        /* Check if we support this request */
        switch (radreq->code) {
        case RT_AUTHENTICATION_REQUEST:
        case RT_AUTHENTICATION_ACK:
        case RT_AUTHENTICATION_REJECT:
        case RT_ACCESS_CHALLENGE:
                type = R_AUTH;
                break;
        case RT_ACCOUNTING_REQUEST:
        case RT_ACCOUNTING_RESPONSE:
#if defined(RT_ASCEND_EVENT_REQUEST)            
        case RT_ASCEND_EVENT_REQUEST:
#endif
                type = R_ACCT;
                break;
        default:
                stat_inc(acct, radreq->ipaddr, num_unknowntypes);
                radlog_req(L_NOTICE, radreq, _("unknown request code %d"), 
                           radreq->code); 
                return -1;
        }       
        
        /* Copy the static data into malloc()ed memory. */
        radreq->data = emalloc(radreq->data_len);
        memcpy(radreq->data, buf, radreq->data_len);
        radreq->data_alloced = 1;

        return rad_request_handle(type, radreq, activefd);
}

int
rad_req_setup(req)
        REQUEST *req;
{
        RADIUS_REQ *radreq = req->data;
        
        debug(1, ("called"));

        switch (radreq->code) {

        case RT_AUTHENTICATION_REQUEST:
                /*
                 *      Check request against hints and huntgroups.
                 */
                stat_inc(auth, radreq->ipaddr, num_access_req);
                if (rad_auth_init(radreq, req->fd) < 0) 
                        return 1;
                /*FALLTHRU*/
        case RT_ACCOUNTING_REQUEST:
                if (avl_find(radreq->request, DA_USER_NAME) == NULL)
                        break;
                if (proxy_send(radreq, req->fd) != 0) {
                        req->type = R_PROXY;
                        return 0;
                }
                break;

        case RT_AUTHENTICATION_ACK:
        case RT_AUTHENTICATION_REJECT:
        case RT_ACCOUNTING_RESPONSE:
	case RT_ACCESS_CHALLENGE:
                if (proxy_receive(radreq, req->fd) < 0) 
                        return 1;
                break;
        }
        return 0;
}

/* ************************************************************************* */
/* SNMP request handling functions */
#ifdef USE_SNMP

/*ARGSUSED*/
int
snmp_respond(fd, sa, salen, buf, size)
        int fd;
        struct sockaddr *sa;
        int salen;
        u_char *buf;
        int size;
{
        struct snmp_req *snmp_req;
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        
        if (snmp_req = rad_snmp_respond(buf, size, sin)) 
                return rad_request_handle(R_SNMP, snmp_req, fd);

        return 0;
}

#endif

/* ************************************************************************* */

int
radiusd_mutex_lock(mutex, type)
	pthread_mutex_t *mutex;
	int type;
{
	int rc;
	struct timeval now, end, tv;

	radiusd_get_timeout(type, &end);
	while ((rc = pthread_mutex_trylock(mutex)) == EBUSY) {
		gettimeofday(&now, NULL);
		if (timercmp(&now, &end, >=))
			break;
		tv.tv_sec = 0;
		tv.tv_usec = 10;
		select(0, NULL, NULL, NULL, &tv);
	}
	return rc;
}

int
radiusd_mutex_unlock(mutex)
	pthread_mutex_t *mutex;
{
	return pthread_mutex_unlock(mutex);
}

void
radiusd_pidfile_write(name)
	char *name;
{
        pid_t pid = getpid();
        char *p = mkfilename(radpid_dir, name);
	FILE *fp = fopen(p, "w"); 
	if (fp) {
                fprintf(fp, "%d\n", pid);
                fclose(fp);
        }
        efree(p);
}	

pid_t
radiusd_pidfile_read(name)
	char *name;
{
	long val;
	char *p = mkfilename(radpid_dir, name);
	FILE *fp = fopen(p, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%ld", &val) != 1)
		val = -1;
	fclose(fp);
	efree(p);
	return (pid_t) val;
}

void
radiusd_pidfile_remove(name)
	char *name;
{
	char *p = mkfilename(radpid_dir, name);
	unlink(p);
	efree(p);
}

int
radiusd_get_timeout(type, tv)
	int type;
	struct timeval *tv;
{
	gettimeofday(tv, NULL);
	tv->tv_sec += request_class[type].ttl;
	return 0;
}

