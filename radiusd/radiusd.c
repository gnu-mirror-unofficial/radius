/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_RADIUSD_C
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include <radiusd.h>
#include <radargp.h>
#include <radutmp.h>
#include <rewrite.h>
#include <argcv.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#ifdef USE_SQL
# include <radsql.h>
#endif

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


/* *************************** Global Variables **************************** */

int        debug_flag; /* can be raised from debugger only */
int        log_mode;

static int foreground; /* Stay in the foreground */
int spawn_flag; 

int use_dbm = 0;
int auth_detail = 0;
int acct_detail = 1;      
int strip_names;
int suspend_flag;

#define CMD_NONE     0 /* No command */
#define CMD_CLEANUP  1 /* Cleanup finished children */
#define CMD_RELOAD   2 /* The reload of the configuration is needed */
#define CMD_RESTART  3 /* Try to restart */
#define CMD_MEMINFO  4 /* Dump memory usage statistics */
#define CMD_DUMPDB   5 /* Dump authentication database */
#define CMD_SHUTDOWN 6 /* Stop immediately */
#define CMD_SUSPEND  7 /* Suspend service */
#define CMD_CONTINUE 8 /* Continue after suspend */

int daemon_command = CMD_NONE;

static INPUT *radius_input;   /* The input channels */

#ifdef USE_SNMP
int snmp_port;
serv_stat saved_status;
#endif

                    /* These are the user flag marking attributes that
		       can be used in comparing ... */
int auth_comp_flag; /* ... authentication requests */ 
int acct_comp_flag; /* ... accounting requests */

int checkrad_assume_logged = 1;
size_t max_requests = MAX_REQUESTS;
size_t max_children = MAX_CHILDREN;
unsigned process_timeout = PROCESS_TIMEOUT;
unsigned radiusd_write_timeout = 0;
unsigned radiusd_read_timeout = 0;
char *exec_user = NULL;

UINT4 warning_seconds;
int use_guile;
char *message_text[MSG_COUNT];
UINT4 myip = INADDR_ANY;
UINT4 ref_ip = INADDR_ANY;
int auth_port;
int acct_port;

pid_t radiusd_pid;
int radius_mode = MODE_DAEMON;    

/* Invocation vector for self-restart */
int  xargc;
char **xargv;
char *x_debug_spec;

/* Forward declarations */
static RETSIGTYPE sig_handler(int sig);
void radiusd_main_loop();
static size_t radius_count_channels();
void radiusd_run_preconfig_hooks(void *data);
static int test_shell();	
struct cfg_stmt config_syntax[];


/* ************************ Command Line Parser **************************** */

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'A':
                auth_detail++;
                break;
		
        case 'a':
                radacct_dir = estrdup(optarg);
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
                radlog_dir = estrdup(optarg);
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
                        argp_error(state,
				   _("radiusd compiled without DBM support"));
                        exit(1);
#endif
                        break;
			
                case 'c':
                        radius_mode = MODE_CHECKCONF;
                        break;
			
                default:
                        argp_error(state, _("unknown mode: %s"), arg);
			exit(1);
		}
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
                auth_port = atoi(optarg);
		acct_port = auth_port+1;
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


/* *********************** Configuration Functions ************************* */
void
set_config_defaults()
{
        exec_user  = estrdup("daemon");
        username_valid_chars = estrdup(".-_!@#$%^&\\/");
        message_text[MSG_ACCOUNT_CLOSED] =
                estrdup(_("Sorry, your account is currently closed\n"));
        message_text[MSG_PASSWORD_EXPIRED] =
                estrdup(_("Password has expired\n"));
        message_text[MSG_PASSWORD_EXPIRE_WARNING] =
                estrdup(_("Password will expire in %R{Password-Expire-Days} Days\n"));
        message_text[MSG_ACCESS_DENIED] =
                estrdup(_("\nAccess denied\n"));
        message_text[MSG_REALM_QUOTA] =
                estrdup(_("\nRealm quota exceeded - access denied\n"));
        message_text[MSG_MULTIPLE_LOGIN] =
                estrdup(_("\nYou are already logged in %R{Simultaneous-Use} times - access denied\n"));
        message_text[MSG_SECOND_LOGIN] =
                estrdup(_("\nYou are already logged in - access denied\n"));
        message_text[MSG_TIMESPAN_VIOLATION] =
                estrdup(_("You are calling outside your allowed timespan\n"));
}

static int
get_port_number(char *name, char *proto, int defval)
{
        struct servent *svp;

	svp = getservbyname(name, proto);
	return svp ? ntohs(svp->s_port) : defval;
}

unsigned 
max_ttl(time_t *t)
{
	unsigned i, delta = 0;

	for (i = 0; i < R_MAX; i++)
		if (delta < request_class[i].ttl)
			delta = request_class[i].ttl;
	if (t) {
		time(t);
		*t += delta;
	}
	return delta;
}

static void
terminate_subprocesses()
{
	int kill_sent = 0;
	time_t t;
	
        /* Flush any pending requests and empty the request queue */
	radiusd_flush_queue();
	request_init_queue();
	
	/* Terminate all subprocesses */
	radlog(L_INFO, _("Terminating the subprocesses"));
	rpp_kill(-1, SIGTERM);
	
	max_ttl(&t);
	
	while (rpp_count()) {
		sleep(1);
		radiusd_cleanup();
		if (time(NULL) >= t) {
			if (kill_sent) {
				radlog(L_CRIT, _("%d processes left!"),
					rpp_count());
				break;
			}
			max_ttl(&t);
			rpp_kill(-1, SIGKILL);
			kill_sent = 1;
		}
	}
}

static void
radiusd_preconfig_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	terminate_subprocesses();
	input_close_channels(radius_input);
}

static void
radiusd_postconfig_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	if (radius_mode = MODE_DAEMON && radius_count_channels() == 0) {
		radlog(L_ALERT,
		       _("Radiusd is not listening on any port. Trying to continue anyway..."));
	}
}

void
radiusd_setup()
{
	int i;

	/* Close unneeded file descriptors */
        for (i = getmaxfd(); i >= 3; i--)
                close(i);
        /* Determine default port numbers for authentication and accounting */
	if (auth_port == 0) 
		auth_port = get_port_number("radius", "udp", DEF_AUTH_PORT);
	if (acct_port == 0)
		acct_port = get_port_number("radacct", "udp", auth_port+1);
        srand(time(NULL));

	/* Register radiusd hooks first. This ensures they will be
	   executed after all other hooks */
	radiusd_set_preconfig_hook(radiusd_preconfig_hook, NULL, 0);
	radiusd_set_postconfig_hook(radiusd_postconfig_hook, NULL, 0);
	
        snmp_init(0, 0, (snmp_alloc_t)emalloc, (snmp_free_t)efree);
}

void
common_init()
{
	radlog(L_INFO, _("Starting"));

	radiusd_pid = getpid();
	radius_input = input_create();
	input_register_method(radius_input, "rpp", 0,
			      rpp_input_handler,
			      rpp_input_close,
			      NULL);
	input_register_method(radius_input, "udp", 1,
			      udp_input_handler,
			      udp_input_close,
			      udp_input_cmp);
#ifdef HAVE_SETVBUF
        setvbuf(stdout, NULL, _IOLBF, 0);
#endif
	radiusd_signal_init(sig_handler);
	radiusd_reconfigure();
	radpath_init();
#ifdef USE_SNMP
        snmpserv_init(&saved_status);
#endif		
	radlog(L_INFO, _("Ready"));
}


/* ************************** Core of radiusd ****************************** */
void
radiusd_daemon()
{
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
        signal(SIGHUP, SIG_IGN);

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

int
radiusd_master()
{
	return radiusd_pid == getpid();
}
	

/* ****************************** Main function **************************** */

void
radiusd_main()
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
                exit(builddbm(NULL));
#endif
		
        case MODE_DAEMON:
		if (myip != INADDR_ANY)
			ref_ip = myip;
		else
			ref_ip = get_first_ip();
		if (ref_ip == INADDR_ANY)
		    radlog(L_ALERT, _("can't find out my own IP address"));
		
		chdir("/");
		umask(022);

                if (!foreground)
                        radiusd_daemon();
		
                common_init();
        }

	radiusd_pidfile_write(RADIUSD_PID_FILE);

        radiusd_main_loop();
}

void
radiusd_start()
{
#ifdef USE_SERVER_GUILE
	scheme_main();
#else
	radiusd_main();
#endif
}

int
main(int argc, char **argv)
{
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

	radiusd_setup();
	radiusd_start();
	/*NOTREACHED*/
}

static int
snmp_request_to_command()
{
#ifdef USE_SNMP
	if (server_stat && server_stat->auth.status != saved_status) {
		saved_status = server_stat->auth.status;
		switch (server_stat->auth.status) {
		case serv_reset:
			return CMD_RESTART;

		case serv_init:
			return CMD_RELOAD;

		case serv_running:
			return CMD_CONTINUE;

		case serv_suspended:
			return CMD_SUSPEND;

		case serv_shutdown:
			return CMD_SHUTDOWN;

		case serv_other:
			/* nothing */;
		}
	}
#endif	
	return CMD_NONE;
}

void
radiusd_suspend()
{
	if (suspend_flag == 0) {
		terminate_subprocesses();
		radlog(L_NOTICE, _("RADIUSD SUSPENDED"));
		suspend_flag = 1;
	}
}

void
radiusd_continue()
{
	if (suspend_flag) {
		terminate_subprocesses();
		suspend_flag = 0;
#ifdef USE_SNMP
		server_stat->auth.status = serv_running;
		server_stat->acct.status = serv_running;
#endif
	}
}

static void
check_reload()
{
	if (daemon_command == CMD_NONE)
		daemon_command = snmp_request_to_command();
	
        switch (daemon_command) {
	case CMD_CLEANUP:
		radiusd_cleanup();
		break;
		
        case CMD_RELOAD:
                radlog(L_INFO, _("Reloading configuration now"));
                radiusd_reconfigure();
                break;
		
        case CMD_RESTART:
                radiusd_restart();
                break;
		
        case CMD_MEMINFO:
//                meminfo();
                break;
		
        case CMD_DUMPDB:
                radlog(L_INFO, _("Dumping users db to `%s'"),
		       RADIUS_DUMPDB_NAME);
                dump_users_db();
                break;

	case CMD_SUSPEND:
		radiusd_suspend();
		break;

	case CMD_CONTINUE:
		radiusd_continue();
		break;
		
	case CMD_SHUTDOWN:
		radiusd_exit();
		break;
        }
        daemon_command = CMD_NONE;
}

void
radiusd_register_input_fd(char *name, int fd, void *data)
{
	input_register_channel(radius_input, name, fd, data);
}

void
radiusd_close_channel(int fd)
{
	input_close_channel_fd(radius_input, fd);
}

void
radiusd_cleanup()
{
	pid_t pid;
	int status;
	char buffer[128];
	
        for (;;) {

		pid = waitpid((pid_t)-1, &status, WNOHANG);
                if (pid <= 0)
                        break;

		format_exit_status(buffer, sizeof buffer, status);
		radlog(L_NOTICE, "child %d %s", pid, buffer);

		rpp_remove(pid);
	}
}

void
radiusd_restart()
{
	pid_t pid;
	
	radlog(L_NOTICE, _("restart initiated"));
	if (xargv[0][0] != '/') {
		radlog(L_ERR,
		       _("can't restart: not started as absolute pathname"));
		return;
	}

	radiusd_run_preconfig_hooks(NULL);

	if (foreground)
		pid = 0; /* make-believe we're child */
	else 
		pid = fork();
	if (pid < 0) {
		radlog(L_CRIT|L_PERROR,
		       _("rad_restart: cannot fork"));
		return;
	}
	
	radiusd_signal_init(SIG_DFL);
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



static int
radiusd_rpp_wait(void *arg)
{
	time_t *tp = arg;
	struct timeval tv;

	if (time(NULL) > *tp)
		return 1;
	
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	input_select_channel(radius_input, "rpp", &tv);
	return 0;
}

void
radiusd_flush_queue()
{
	time_t t;
	max_ttl(&t);
	rpp_flush(radiusd_rpp_wait, &t);
}
		
void
radiusd_exit()
{
        stat_done();
	radiusd_pidfile_remove(RADIUSD_PID_FILE);
	
	radiusd_flush_queue();
	radlog(L_CRIT, _("Normal shutdown."));

	rpp_kill(-1, SIGTERM);
	radiusd_exit0();
}

void
radiusd_exit0()
{
#ifdef USE_SQL
        radiusd_sql_shutdown();
#endif
        exit(0);
}

void
radiusd_main_loop()
{
        radlog(L_INFO, _("Ready to process requests."));

        for (;;) {
		check_reload();
		input_select(radius_input, NULL);
	}
}


/* ************************ Coniguration Functions ************************* */

struct hook_rec {
	void (*function)(void *func_data, void *call_data);
	void *data;
	int once; /* Run once and remove */
};

static LIST /* of struct hook_rec */ *preconfig;
static LIST /* of struct hook_rec */ *postconfig;

void
radiusd_set_preconfig_hook(void (*f)(void *, void *), void *p, int once)
{
	struct hook_rec *hp = emalloc(sizeof(*hp));
	hp->function = f;
	hp->data = p;
	hp->once = once;
	if (!preconfig)
		preconfig = list_create();
	list_prepend(preconfig, hp);
}

void
radiusd_set_postconfig_hook(void (*f)(void *, void *), void *p, int once)
{
	struct hook_rec *hp = emalloc(sizeof(*hp));
	hp->function = f;
	hp->data = p;
	hp->once = once;
	if (!postconfig)
		postconfig = list_create();
	list_prepend(postconfig, hp);
}

struct hook_runtime_closure {
	LIST *list;
	void *call_data;
};

static int
_hook_call(void *item, void *data)
{
	struct hook_rec *hp = item;
	struct hook_runtime_closure *clos = data;
	hp->function(hp->data, clos->call_data);
	if (hp->once) {
		list_remove(clos->list, hp, NULL);
		efree(hp);
	}
	return 0;
}

void
radiusd_run_preconfig_hooks(void *data)
{
	struct hook_runtime_closure clos;
	clos.list = preconfig;
	clos.call_data = data;
	list_iterate(clos.list, _hook_call, &clos);
}

void
radiusd_run_postconfig_hooks(void *data)
{
	struct hook_runtime_closure clos;
	clos.list = postconfig;
	clos.call_data = data;
	list_iterate(clos.list, _hook_call, &clos);
}

void
radiusd_reconfigure()
{
        int rc = 0;
        char *filename;

	radiusd_run_preconfig_hooks(NULL);
	
	radlog(L_INFO, _("Loading configuration files."));
	/* Read main configuration file */
        filename = mkfilename(radius_dir, RADIUS_CONFIG);
        cfg_read(filename, config_syntax, NULL);
	efree(filename);

	/* Read other files */
        rc = reload_config_file(reload_all);
        
        if (rc) {
                radlog(L_CRIT, _("Errors reading config file - EXITING"));
                exit(1);
        }

	radiusd_run_postconfig_hooks(NULL);
}


/* ***************************** Signal Handling *************************** */

static RETSIGTYPE
sig_handler(int sig)
{
        switch (sig) {
	case SIGHUP:
		daemon_command = CMD_RELOAD;
                break;

	case SIGUSR1:
		daemon_command = CMD_MEMINFO;
		break;

        case SIGUSR2:
		daemon_command = CMD_DUMPDB;
		break;

	case SIGCHLD:
		daemon_command = CMD_CLEANUP;
		break;

	case SIGTERM:
	case SIGQUIT:
		daemon_command = CMD_SHUTDOWN;
		break;
		
	case SIGPIPE:
		/*FIXME: Any special action? */
		daemon_command = CMD_CLEANUP;
		break;

	default:
		abort();
	}
	signal(sig, sig_handler);
}

void
radiusd_signal_init(RETSIGTYPE (*hp)(int sig))
{
	static int signum[] = {
		SIGHUP, SIGUSR1, SIGUSR2, SIGQUIT,
		SIGTERM, SIGCHLD, SIGBUS, 
		SIGFPE, SIGSEGV, SIGILL, SIGPIPE
	};
	int i;

	for (i = 0; i < sizeof(signum)/sizeof(signum[0]); i++)
		signal(signum[i], hp);
}


/* ****************************** Test Shell ******************************* */
   
static char buf[128];
int doprompt;

static char *
moreinput(char *buf, size_t bufsize)
{
        if (doprompt)
                printf("%% ");
        return fgets(buf, bufsize, stdin);
}

static int
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
					
				case Undefined:
					printf("Undefined");
					break;

				default:
					abort();
                                }
                                printf("\n");
                        }
                        break;
                case 's':
                        printf("%d\n", parse_rewrite(tok));
                        break;
                case 'm': /*memory statistics */
                        //meminfo();
                        break;
                default:
                        printf("no command\n");
                }
        }
        return 0;
}


/* ************************************************************************* */

void
radiusd_pidfile_write(char *name)
{
        pid_t pid = getpid();
        char *p = mkfilename(radpid_dir, name);
	FILE *fp = fopen(p, "w"); 
	if (fp) {
                fprintf(fp, "%lu\n", (u_long) pid);
                fclose(fp);
        }
        efree(p);
}	

pid_t
radiusd_pidfile_read(char *name)
{
	unsigned long val;
	char *p = mkfilename(radpid_dir, name);
	FILE *fp = fopen(p, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%lu", &val) != 1)
		val = -1;
	fclose(fp);
	efree(p);
	return (pid_t) val;
}

void
radiusd_pidfile_remove(char *name)
{
	char *p = mkfilename(radpid_dir, name);
	unlink(p);
	efree(p);
}



/* ************************************************************************* */
static u_char recv_buffer[RAD_BUFFER_SIZE];

struct udp_data {
	int type;
	struct sockaddr_in addr;
};

int
udp_input_handler(int fd, void *data)
{
        struct sockaddr sa;
	socklen_t salen = sizeof (sa);
	int size;
	struct udp_data *sd = data;
	
	size = recvfrom(fd, (char *) recv_buffer, sizeof(recv_buffer),
			0, &sa, &salen);
	if (size < 0) 
		request_fail(sd->type, (struct sockaddr_in*)&sa);
	else {
		REQUEST *req = request_create(sd->type,
					      fd,
					      (struct sockaddr_in*)&sa,
					      recv_buffer, size);

		if (request_handle(req,
				   spawn_flag ?
				   rpp_forward_request : request_respond))
			request_free(req);
	}
	return 0;
}

int
udp_input_close(int fd, void *data)
{
	close(fd);
	efree(data);
	return 0;
}

int
udp_input_cmp(const void *a, const void *b)
{
	const struct udp_data *sda = a;
	const struct udp_data *sdb = b;

	if (sda->addr.sin_port != sdb->addr.sin_port)
		return 1;
	if (sda->addr.sin_addr.s_addr == INADDR_ANY
	    || sdb->addr.sin_addr.s_addr == INADDR_ANY)
		return 0;
	return sda->addr.sin_addr.s_addr != sdb->addr.sin_addr.s_addr;
}

int
udp_open(int type, UINT4 ipaddr, int port, int nonblock)
{
	int fd;
	struct sockaddr_in s;
	struct udp_data *p;
	
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(ipaddr);
        s.sin_port = htons(port);
	if (p = input_find_channel(radius_input, "udp", &s)) {
		char buffer[DOTTED_QUAD_LEN];
		radlog(L_ERR,
		       _("socket %s:%d is already assigned for %s"),
		       ip_iptostr(ipaddr, buffer),
		       port,
		       request_class[p->type].name);
		return 1;
	}

        fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (nonblock) 
		set_nonblocking(fd);
        if (fd < 0) {
                radlog(L_CRIT|L_PERROR, "%s socket",
		       request_class[type].name);
		return 1;
        }
        if (bind(fd, (struct sockaddr*) &s, sizeof(s)) < 0) {
                radlog(L_CRIT|L_PERROR, "%s bind", request_class[type].name);
		close(fd);
		return 1;
	}

	p = emalloc(sizeof(*p));
	p->type = type;
	p->addr = s;
	input_register_channel(radius_input, "udp", fd, p);
	return 0;
}

static int
channel_counter(void *item, void *data)
{
	struct udp_data *p = item;
	if (p->type == R_AUTH || p->type == R_ACCT)
		++*(size_t*)data;
	return 0;
}

static size_t
radius_count_channels()
{
	size_t count = 0;
	
	input_iterate_channels(radius_input, "udp", channel_counter, &count);
	return count;
}


/* ************************************************************************* */

static int _opened_auth_sockets;
static int _opened_acct_sockets;

static int
rad_cfg_listen_auth(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data)
{
	int i, errcnt = 0;
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) {
		for (i = 1; i < argc; i++) 
			if (udp_open(R_AUTH,
				     argv[i].v.host.ipaddr,
				     argv[i].v.host.port > 0 ?
				     argv[i].v.host.port : auth_port,
				     0))
				errcnt++;
	}
	if (errcnt == 0)
		_opened_auth_sockets++;
	return 0;
}

int
auth_stmt_begin(int finish, void *block_data, void *handler_data)
{
	if (!finish) 
		_opened_auth_sockets = 0;
	else if (radius_mode == MODE_DAEMON && !_opened_auth_sockets) 
		udp_open(R_AUTH, INADDR_ANY, auth_port, 0);
	return 0;
}

static int
rad_cfg_listen_acct(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data)
{
	int i, errcnt = 0;
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) {
		for (i = 1; i < argc; i++) 
			udp_open(R_ACCT,
				 argv[i].v.host.ipaddr,
				 argv[i].v.host.port > 0 ?
				 argv[i].v.host.port : acct_port,
				 0);
	}
	_opened_acct_sockets++;
	return 0;
}
		
int
acct_stmt_begin(int finish, void *block_data, void *handler_data)
{
	if (!finish) 
		_opened_acct_sockets = 0;
	else if (radius_mode == MODE_DAEMON && !_opened_acct_sockets) 
		udp_open(R_ACCT, INADDR_ANY, acct_port, 0);
	return 0;
}

struct cfg_stmt option_stmt[] = {
	{ "source-ip", CS_STMT, NULL, cfg_get_ipaddr, &myip,
	  NULL, NULL },
	{ "max-requests", CS_STMT, NULL, cfg_get_integer, &max_requests,
	  NULL, NULL },
	{ "max-threads", CS_STMT, NULL, cfg_get_integer, &max_children,
	  NULL, NULL },
	{ "max-processes", CS_STMT, NULL, cfg_get_integer, &max_children,
	  NULL, NULL },
	{ "process-idle-timeout", CS_STMT, NULL, cfg_get_integer, &process_timeout,
	  NULL, NULL },
	{ "master-read-timeout", CS_STMT, NULL,
	  cfg_get_integer, &radiusd_read_timeout, NULL, NULL },
	{ "master-write-timeout", CS_STMT, NULL,
	  cfg_get_integer, &radiusd_write_timeout, NULL, NULL },
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
	/* Obsolete statements */
	{ "usr2delay", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
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
	/* Obsolete statements */
	{ "spawn", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
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
	/* Obsolete statements */
	{ "spawn", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
	{ NULL, }
};

struct cfg_stmt proxy_stmt[] = {
	{ "max-requests", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_obsolete, NULL, NULL, NULL },
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
