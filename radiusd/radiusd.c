/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,2007,
   2008 Free Software Foundation
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

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
#include <radius/radargp.h>
#include <radius/radutmp.h>
#include <radius/argcv.h>
#include <rewrite.h>
#include <snmp/asn1.h>
#include <snmp/snmp.h>
#include <timestr.h>

const char *argp_program_version = "radiusd (" PACKAGE ") " VERSION;
static char doc[] = N_("GNU radius daemon");

#define SHOW_DEFAULTS_OPTION 256
#define SELECT_PORTS_OPTION 257

static struct argp_option options[] = {
#define GRP 100	
        {NULL, 0, NULL, 0,
         N_("radiusd specific switches:"), GRP},
        {"foreground", 'f', NULL, 0,
         N_("Stay in foreground"), GRP+1},
        {"mode", 'm', "{t|c|b}", 0,
         N_("Select operation mode: test, checkconf, builddbm."), GRP+1},
        {"single-process", 's', NULL, 0,
         N_("Run in single process mode"), GRP+1},
        {"pid-file-dir", 'P', N_("DIR"), 0,
         N_("Store pidfile in DIR"), GRP+1},
	{"show-defaults", SHOW_DEFAULTS_OPTION, NULL, 0,
	 N_("Show compilation defaults"), GRP+1},
	{"quiet", 'q', NULL, 0,
	 N_("Quiet mode (valid only with --mode)"), GRP+1},
	{"select-free-ports", SELECT_PORTS_OPTION, N_("FILE"), 0,
	 N_("Select port numbers from available UDP ports"), GRP+1 },
#undef GRP
#define GRP 200
	{NULL, 0, NULL, 0,
         N_("Daemon configuration options. Please use raddb/config instead."),
	 GRP},
	
        {"log-auth-detail", 'A', 0, 0,
         N_("Do detailed authentication logging"), GRP+1},
        {"acct-directory",  'a', N_("DIR"), 0,
         N_("Set accounting directory"), GRP+1},
#ifdef USE_DBM
        {"dbm", 'b', NULL, 0,
         N_("Enable DBM support"), GRP+1},
#endif
        {"logging-directory", 'l', N_("DIR"), 0, 
         N_("Set logging directory name"), GRP+1},
        {"do-not-resolve", 'n', NULL, 0,
         N_("Do not resolve IP addresses"), GRP+1},
        {"ip-address", 'i', N_("IPADDR"), 0,
         N_("Listen on IPADDR"), GRP+1},
        {"port", 'p', "NUMBER", 0,
         N_("Set authentication port number"), GRP+1},
        {"log-stripped-names", 'S', NULL, 0,
         N_("Strip prefixes/suffixes off user names before logging"), GRP+1},
        {"debug", 'x', N_("DEBUGSPEC"), 0,
         N_("Set debugging level"), GRP+1},
        {"log-auth", 'y', NULL, 0,
         N_("Log authentications"), GRP+1},
        {"log-auth-pass", 'z', NULL, 0,
         N_("Log users' passwords"), GRP+1},
#undef GRP
        {NULL, 0, NULL, 0, NULL, 0}
};


/* *************************** Global Variables **************************** */

int        debug_flag;     /* can be raised from debugger only */
int        log_mode;       /* logging mode */
int        console_logging_priority = -1; /* Default priority for console
					     logging */
char       *auth_log_hook; /* Authentication logging hook function */

static int foreground; /* Stay in the foreground */
int spawn_flag;        /* Whether to spawn new children for handling
			  the requests */

int use_dbm = 0;       /* Use DBM storage */
int auth_detail = 0;   /* Produce detailed logs of authentication packets */
char *auth_detail_template; /* Template for filenames of these logs */
int acct_detail = 1;   /* Produce detailed logs of accounting packets */
char *acct_detail_template; /* Template for filenames of these logs */
int acct_system = 1;   /* Run system accounting into radutmp/radwtmp files */
int auth_trace_rules = 0; /* Produce trace logs for each auth request */
int acct_trace_rules = 0; /* Produce trace logs for each acct request */
int strip_names;          /* Strip preffixes/suffixes off the usernames */
int suspend_flag;         /* Suspend processing of RADIUS requests */
int auth_reject_malformed_names = 0; /* Respond with Access-Reject packets
					for requests with malformed user
					names */

char *select_free_ports;
FILE *port_file;

RADIUS_USER radiusd_user; /* Run the daemon with this user privileges */
RADIUS_USER exec_user;    /* Run the user programs with this user privileges */

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
unsigned radiusd_write_timeout = RADIUSD_WRITE_TIMEOUT;
unsigned radiusd_read_timeout = RADIUSD_READ_TIMEOUT;

grad_uint32_t warning_seconds;
int use_guile;
char *message_text[MSG_COUNT];
grad_uint32_t myip = INADDR_ANY;
grad_uint32_t ref_ip = INADDR_ANY;
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
                grad_acct_dir = grad_estrdup(arg);
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
                grad_log_dir = grad_estrdup(arg);
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
                grad_resolve_hostnames = 0;
                break;
		
        case 'i':
                if ((myip = grad_ip_gethostaddr(arg)) == 0)
                        fprintf(stderr,
                                _("invalid IP address: %s"),
                                arg);
                break;
		
        case 'P':
                grad_pid_dir = arg;
                break;
		
        case 'p':
                auth_port = atoi(arg);
		acct_port = auth_port+1;
                break;

	case 'q':
		console_logging_priority = GRAD_LOG_ERR;
		break;
		
        case 'S':
                strip_names++;  
                break;
		
        case 's':       /* Single process mode */
                spawn_flag = 0;
                break;

	case SELECT_PORTS_OPTION:
		select_free_ports = arg;
		break;
		
        case 'x':
                x_debug_spec = arg;
                grad_set_debug_levels(arg);
                break;
		
        case 'y':
                log_mode |= RLOG_AUTH;    
                break;
		
        case 'z':
                log_mode |= RLOG_AUTH_PASS;
                break;

	case SHOW_DEFAULTS_OPTION:
		show_compilation_defaults();
		exit(0);
		
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
        grad_common_argp_child,
        NULL, NULL
};


/* *********************** Configuration Functions ************************* */
void
set_config_defaults()
{
        username_valid_chars = grad_estrdup(".-_!@#$%^&\\/");
        message_text[MSG_ACCOUNT_CLOSED] =
                grad_estrdup(_("Sorry, your account is currently closed\n"));
        message_text[MSG_PASSWORD_EXPIRED] =
                grad_estrdup(_("Password has expired\n"));
        message_text[MSG_PASSWORD_EXPIRE_WARNING] =
                grad_estrdup(_("Password will expire in %R{Password-Expire-Days} Days\n"));
        message_text[MSG_ACCESS_DENIED] =
                grad_estrdup(_("\nAccess denied\n"));
        message_text[MSG_REALM_QUOTA] =
                grad_estrdup(_("\nRealm quota exceeded - access denied\n"));
        message_text[MSG_MULTIPLE_LOGIN] =
                grad_estrdup(_("\nYou are already logged in %R{Simultaneous-Use} times - access denied\n"));
        message_text[MSG_SECOND_LOGIN] =
                grad_estrdup(_("\nYou are already logged in - access denied\n"));
        message_text[MSG_TIMESPAN_VIOLATION] =
                grad_estrdup(_("You are calling outside your allowed timespan\n"));
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
	grad_log(GRAD_LOG_INFO, _("Terminating the subprocesses"));
	rpp_kill(-1, SIGTERM);
	
	max_ttl(&t);
	
	while (rpp_count()) {
		sleep(1);
		radiusd_cleanup();
		if (time(NULL) >= t) {
			if (kill_sent) {
				int n = rpp_count();
				grad_log(GRAD_LOG_CRIT,
				         ngettext("%d process left!",
					 	  "%d processes left!",
						  n),
				         n);
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
	if (radius_mode == MODE_DAEMON && radius_count_channels() == 0) {
		if (foreground) {
			grad_log(GRAD_LOG_ALERT,
			         _("Radiusd is not listening on any port."));
			exit(1);
		} else
			grad_log(GRAD_LOG_ALERT,
			         _("Radiusd is not listening on any port. Trying to continue anyway..."));
	}
}

static void
daemon_postconfig_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	system_acct_init();
}

void
radiusd_setup()
{
	int i;

	/* Close unneeded file descriptors */
        for (i = grad_max_fd(); i >= 3; i--)
                close(i);
        /* Determine default port numbers for authentication and accounting */
	if (auth_port == 0) 
		auth_port = get_port_number("radius", "udp", DEF_AUTH_PORT);
	if (acct_port == 0)
		acct_port = get_port_number("radacct", "udp", auth_port+1);
#ifdef USE_SNMP
	snmp_port = get_port_number("snmp", "udp", 161);
#endif
        srand(time(NULL));
	
#ifdef HAVE_CRYPT_SET_FORMAT
	/* MD5 hashes are handled by libgnuradius function md5crypt(). To
	   handle DES hashes it falls back to system crypt(). The behaviour
	   of the latter on FreeBSD depends upon a 'default format'. so e.g.
	   crypt() may generate MD5 hashes even if presented with a valid
	   MD5 salt.
	   
	   To make sure this does not happen, we need to set the default
	   crypt() format. */
	
	crypt_set_format("des");
#endif

	/* Register radiusd hooks first. This ensures they will be
	   executed after all other hooks */
	radiusd_set_preconfig_hook(radiusd_preconfig_hook, NULL, 0);
	radiusd_set_postconfig_hook(radiusd_postconfig_hook, NULL, 0);

	rewrite_init();
	dynload_init();
        snmp_init(0, 0, (snmp_alloc_t)grad_emalloc, (snmp_free_t)grad_free);
	mlc_init();
	sql_init();
}

void
common_init()
{
	grad_log(GRAD_LOG_INFO, _("Starting"));

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
	forward_init();
#ifdef USE_SNMP
        snmpserv_init(&saved_status);
#endif
	acct_init();
	if (select_free_ports) {
		port_file = fopen(select_free_ports, "w");
		if (!port_file) {
			grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR,
				 _("Cannot open output file %s"),
				 select_free_ports);
			exit(1);
		}
	}
				   
	radiusd_reconfigure();

	if (port_file) {
		fclose(port_file);
		port_file = NULL;
		select_free_ports = NULL;
	}
	
	grad_log(GRAD_LOG_INFO, _("Ready"));
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
                grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, "fork");
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
        grad_set_signal(SIGHUP, SIG_IGN);

        /* fork() again so the parent, can exit. This means that we, as a
           non-session group leader, can never regain a controlling
           terminal. */
        switch (pid = fork()) {
        case 0:
                break;
        case -1:
                grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, "fork");
                exit(1);
        default:
                exit(0);
        }

        /* This is needed for messages generated by guile
           functions.
	   FIXME: The compiled-in value of grad_log_dir is used */
        p = grad_mkfilename(grad_log_dir, "radius.stderr");
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
        grad_free(p);
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
                tsh();
                
#ifdef USE_DBM          
        case MODE_BUILDDBM:
                common_init();
                exit(builddbm(NULL));
#endif
		
        case MODE_DAEMON:
		if (myip != INADDR_ANY)
			ref_ip = myip;
		else
			ref_ip = grad_first_ip();
		if (ref_ip == INADDR_ANY)
		    grad_log(GRAD_LOG_ALERT, _("can't find out my own IP address"));
		
		chdir("/");
		umask(022);

                if (!foreground)
                        radiusd_daemon();
		/* Install daemon-specific hook */
		radiusd_set_postconfig_hook(daemon_postconfig_hook,
					    NULL, 0);
                common_init();
        }

	radiusd_pidfile_write(RADIUSD_PID_FILE);

	if (radiusd_user.username) {
		char *p;
		log_change_owner(&radiusd_user);
		p = grad_mkfilename(grad_log_dir, "radius.stderr");
		chown(p, radiusd_user.uid, radiusd_user.gid);
		grad_free(p);
		radius_switch_to_user(&radiusd_user);
	}

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
        grad_app_setup();
	grad_set_logger(radiusd_logger);
	
        /* save the invocation */
        xargc = argc;
        xargv = argv;

        /* Set up some default values */
        set_config_defaults();

        /* Process the options.  */
        argp_program_version_hook = version;
        if (grad_argp_parse(&argp, &argc, &argv, 0, NULL, NULL))
                return 1;

        log_set_default("default.log", -1, -1);
        if (radius_mode != MODE_DAEMON)
                log_set_to_console(-1, console_logging_priority);

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
		grad_log(GRAD_LOG_NOTICE, _("RADIUSD SUSPENDED"));
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
                grad_log(GRAD_LOG_INFO, _("Reloading configuration now"));
                radiusd_reconfigure();
                break;
		
        case CMD_RESTART:
                radiusd_restart();
                break;
		
        case CMD_MEMINFO:
                break;
		
        case CMD_DUMPDB:
                grad_log(GRAD_LOG_INFO, _("Dumping users db to `%s'"),
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
radiusd_collect_children()
{
	pid_t pid;
	int status;

	for (;;) {
		pid = waitpid((pid_t)-1, &status, WNOHANG);
		if (pid <= 0)
			break;
		rpp_status_changed(pid, status);
	}
}

void
radiusd_cleanup()
{
	rpp_collect_exited ();
}

void
radiusd_restart()
{
	pid_t pid;
	
	grad_log(GRAD_LOG_NOTICE, _("restart initiated"));
	if (xargv[0][0] != '/') {
		grad_log(GRAD_LOG_ERR,
		         _("can't restart: not started as absolute pathname"));
		return;
	}

	radiusd_run_preconfig_hooks(NULL);

	if (foreground)
		pid = 0; /* make-believe we're child */
	else 
		pid = fork();
	if (pid < 0) {
		grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR,
		         _("radiusd_restart: cannot fork"));
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
	grad_log(GRAD_LOG_NOTICE, _("restarting radius"));
	execvp(xargv[0], xargv);
	grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, 
	         _("RADIUS NOT RESTARTED: exec failed"));
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
	grad_log(GRAD_LOG_CRIT, _("Normal shutdown."));

	rpp_kill(-1, SIGTERM);
	radiusd_exit0();
}

void
radiusd_exit0()
{
        radiusd_sql_shutdown();
        exit(0);
}

void
radiusd_main_loop()
{
        grad_log(GRAD_LOG_INFO, _("Ready to process requests."));

        for (;;) {
		log_open(GRAD_LOG_MAIN);
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

static grad_list_t /* of struct hook_rec */ *preconfig;
static grad_list_t /* of struct hook_rec */ *postconfig;

void
radiusd_set_preconfig_hook(void (*f)(void *, void *), void *p, int once)
{
	struct hook_rec *hp = grad_emalloc(sizeof(*hp));
	hp->function = f;
	hp->data = p;
	hp->once = once;
	if (!preconfig)
		preconfig = grad_list_create();
	grad_list_prepend(preconfig, hp);
}

void
radiusd_set_postconfig_hook(void (*f)(void *, void *), void *p, int once)
{
	struct hook_rec *hp = grad_emalloc(sizeof(*hp));
	hp->function = f;
	hp->data = p;
	hp->once = once;
	if (!postconfig)
		postconfig = grad_list_create();
	grad_list_prepend(postconfig, hp);
}

struct hook_runtime_closure {
	grad_list_t *list;
	void *call_data;
};

static int
_hook_call(void *item, void *data)
{
	struct hook_rec *hp = item;
	struct hook_runtime_closure *clos = data;
	hp->function(hp->data, clos->call_data);
	if (hp->once) {
		grad_list_remove(clos->list, hp, NULL);
		grad_free(hp);
	}
	return 0;
}

void
radiusd_run_preconfig_hooks(void *data)
{
	struct hook_runtime_closure clos;
	clos.list = preconfig;
	clos.call_data = data;
	grad_list_iterate(clos.list, _hook_call, &clos);
}

void
radiusd_run_postconfig_hooks(void *data)
{
	struct hook_runtime_closure clos;
	clos.list = postconfig;
	clos.call_data = data;
	grad_list_iterate(clos.list, _hook_call, &clos);
}

void
radiusd_reconfigure()
{
        int rc = 0;
        char *filename;

	radiusd_run_preconfig_hooks(NULL);
	
	grad_log(GRAD_LOG_INFO, _("Loading configuration files."));
	/* Read main configuration file */
        filename = grad_mkfilename(grad_config_dir, RADIUS_CONFIG);
        cfg_read(filename, config_syntax, NULL);
	grad_free(filename);

	/* Read other files */
        rc = reload_config_file(reload_all);
        
        if (rc) {
                grad_log(GRAD_LOG_CRIT, _("Errors reading config file - EXITING"));
                exit(1);
        }

	grad_path_init();
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
		radiusd_collect_children ();
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
	grad_reset_signal(sig, sig_handler);
}

void
radiusd_signal_init(RETSIGTYPE (*hp)(int sig))
{
	static int signum[] = {
		SIGHUP, SIGUSR1, SIGUSR2, SIGCHLD, 
		SIGTERM, SIGQUIT, SIGPIPE
	};
	int i;

	for (i = 0; i < sizeof(signum)/sizeof(signum[0]); i++)
		grad_set_signal(signum[i], hp);
}


/* ************************************************************************* */

void
radiusd_pidfile_write(char *name)
{
        pid_t pid = getpid();
        char *p = grad_mkfilename(grad_pid_dir, name);
	FILE *fp = fopen(p, "w"); 
	if (fp) {
                fprintf(fp, "%lu\n", (u_long) pid);
                fclose(fp);
        }
        grad_free(p);
}	

pid_t
radiusd_pidfile_read(char *name)
{
	unsigned long val;
	char *p = grad_mkfilename(grad_pid_dir, name);
	FILE *fp = fopen(p, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%lu", &val) != 1)
		val = -1;
	fclose(fp);
	grad_free(p);
	return (pid_t) val;
}

void
radiusd_pidfile_remove(char *name)
{
	char *p = grad_mkfilename(grad_pid_dir, name);
	unlink(p);
	grad_free(p);
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
					      &sd->addr,
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
	grad_free(data);
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
udp_open(int type, grad_uint32_t ipaddr, int port, int nonblock)
{
	int fd;
	struct sockaddr_in s;
	struct udp_data *p;

	if (select_free_ports)
		port = 0;
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(ipaddr);
        s.sin_port = htons(port);
	
	if (port && (p = input_find_channel(radius_input, "udp", &s))) {
		char buffer[GRAD_IPV4_STRING_LENGTH];
		grad_log(GRAD_LOG_ERR,
		         _("socket %s:%d is already assigned for %s"),
		         grad_ip_iptostr(ipaddr, buffer),
		         port,
		         request_class[p->type].name);
		return 1;
	}

        fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (nonblock) 
		grad_set_nonblocking(fd);
        if (fd < 0) {
                grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, "%s socket",
		         request_class[type].name);
		return 1;
        }
        if (bind(fd, (struct sockaddr*) &s, sizeof(s)) < 0) {
                grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, 
                         "%s bind", request_class[type].name);
		close(fd);
		return 1;
	}

	if (port == 0) {
		socklen_t len = sizeof(s);
		if (getsockname(fd, &s, &len)) {
			grad_log(GRAD_LOG_CRIT|GRAD_LOG_PERROR, 
				 "%s getsockname", request_class[type].name);
			close(fd);
			return 1;
		}
		port = ntohs(s.sin_port);
		grad_log(GRAD_LOG_INFO, "%s=%u",
			 request_class[type].name, port); 
		fprintf(port_file, "%s=%u\n",
			request_class[type].name, port);
		switch (type) {
		case R_AUTH:
			auth_port = port;
			break;

		case R_ACCT:
			acct_port = port;
			break;

#ifdef USE_SNMP
		case R_SNMP:
			snmp_port = port;
			break;
#endif
		}
	}
		
	p = grad_emalloc(sizeof(*p));
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

	if (argc == 2 && argv[1].type == CFG_BOOLEAN) {
		if (argv[1].v.bool == 0)
			auth_port = 0;
		return 0;
	}
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type == CFG_NETWORK) {
			if (argv[i].v.network.netmask != 0xffffffffL)
				cfg_type_error(CFG_HOST);
		} else if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) {
		for (i = 1; i < argc; i++) {
			grad_uint32_t ip;
			int port;

			if (argv[i].type == CFG_NETWORK) {
				ip = argv[i].v.network.ipaddr;
				port = auth_port;
			} else {
				ip = argv[i].v.host.ipaddr;
				port = argv[i].v.host.port;
			} 
			
			if (udp_open(R_AUTH, ip, port, 0))
				errcnt++;
		}
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
	else if (radius_mode == MODE_DAEMON
		 && !_opened_auth_sockets
		 && auth_port)
		udp_open(R_AUTH, INADDR_ANY, auth_port, 0);
	return 0;
}

static int
rad_cfg_listen_acct(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data)
{
	int i, errcnt = 0;
	
	if (argc == 2 && argv[1].type == CFG_BOOLEAN) {
		if (argv[1].v.bool == 0)
			acct_port = 0;
		return 0;
	}
	
	for (i = 1; i < argc; i++)  
		if (argv[i].type == CFG_NETWORK) {
			if (argv[i].v.network.netmask != 0xffffffffL)
				cfg_type_error(CFG_HOST);
		} else if (argv[i].type != CFG_HOST) {
			cfg_type_error(CFG_HOST);
			errcnt++;
		}
	
	if (errcnt == 0 && radius_mode == MODE_DAEMON) {
		for (i = 1; i < argc; i++) {
			grad_uint32_t ip;
			int port;

			if (argv[i].type == CFG_NETWORK) {
				ip = argv[i].v.network.ipaddr;
				port = acct_port;
			} else {
				ip = argv[i].v.host.ipaddr;
				port = argv[i].v.host.port;
			} 
			
			if (udp_open(R_ACCT, ip, port, 0))
				errcnt++;
		}
	}
	_opened_acct_sockets++;
	return 0;
}
		
int
acct_stmt_begin(int finish, void *block_data, void *handler_data)
{
	if (!finish) 
		_opened_acct_sockets = 0;
	else if (radius_mode == MODE_DAEMON
		 && !_opened_acct_sockets
		 && acct_port)
		udp_open(R_ACCT, INADDR_ANY, acct_port, 0);
	return 0;
}

static int
rad_cfg_user(int argc, cfg_value_t *argv,
	     void *block_data, void *handler_data)
{
	RADIUS_USER *usr = handler_data;

	if (argc != 2 || argv[1].type != CFG_STRING) 
		return 1;
	return radius_get_user_ids((RADIUS_USER *) handler_data,
				   argv[1].v.string);
}

int
option_stmt_end(void *block_data, void *handler_data)
{
	if (exec_user.username && radiusd_user.uid != 0) {
		grad_log(GRAD_LOG_WARN, _("Ignoring exec-program-user"));
		grad_free(exec_user.username);
		exec_user.username = NULL;
	} else if (exec_user.username == NULL
		   && radiusd_user.uid == 0 && getuid() == 0)
		radius_get_user_ids(&exec_user, "daemon");
	return 0;
}

struct cfg_stmt option_stmt[] = {
	{ "source-ip", CS_STMT, NULL, cfg_get_ipaddr, &myip,
	  NULL, NULL },
	{ "max-requests", CS_STMT, NULL, cfg_get_size_t, &max_requests,
	  NULL, NULL },
	{ "max-threads", CS_STMT, NULL, cfg_get_size_t, &max_children,
	  NULL, NULL },
	{ "max-processes", CS_STMT, NULL, cfg_get_size_t, &max_children,
	  NULL, NULL },
	{ "process-idle-timeout", CS_STMT, NULL, cfg_get_unsigned, &process_timeout,
	  NULL, NULL },
	{ "master-read-timeout", CS_STMT, NULL,
	  cfg_get_unsigned, &radiusd_read_timeout, NULL, NULL },
	{ "master-write-timeout", CS_STMT, NULL,
	  cfg_get_unsigned, &radiusd_write_timeout, NULL, NULL },
	{ "exec-program-user", CS_STMT, NULL, rad_cfg_user,
	  &exec_user, NULL, NULL },
	{ "radiusd-user", CS_STMT, NULL, rad_cfg_user,
	  &radiusd_user, NULL, NULL },
	{ "log-dir", CS_STMT, NULL, cfg_get_string, &grad_log_dir,
	  NULL, NULL },
	{ "acct-dir", CS_STMT, NULL, cfg_get_string, &grad_acct_dir,
	  NULL, NULL },
	{ "resolve", CS_STMT, NULL, cfg_get_boolean, &grad_resolve_hostnames,
	  NULL, NULL },
	{ "username-chars", CS_STMT, NULL, cfg_get_string,
	  &username_valid_chars, NULL, NULL },
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
	{ "forward", CS_STMT, NULL, rad_cfg_forward_auth, NULL, NULL, NULL },
	{ "max-requests", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].max_requests, NULL, NULL },
	{ "time-to-live", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].ttl, NULL, NULL },
	{ "request-cleanup-delay", CS_STMT, NULL,
	  cfg_get_integer, &request_class[R_AUTH].cleanup_delay, NULL, NULL },
	{ "detail", CS_STMT, NULL, cfg_get_boolean, &auth_detail,
	  NULL, NULL },
	{ "detail-file-name", CS_STMT, NULL, cfg_get_string,
	  &auth_detail_template, NULL, NULL },
	{ "strip-names", CS_STMT, NULL, cfg_get_boolean, &strip_names,
	  NULL, NULL },
	{ "checkrad-assume-logged", CS_STMT, NULL,
	  cfg_get_boolean, &checkrad_assume_logged,
	  NULL, NULL },
	{ "reject-malformed-names", CS_STMT, NULL,
	  cfg_get_boolean, &auth_reject_malformed_names,
	  NULL, NULL },
	{ "password-expire-warning", CS_STMT, NULL,
	  cfg_get_uint32_t, &warning_seconds,
	  NULL, NULL },
	{ "compare-attribute-flag", CS_STMT, NULL,
	  cfg_get_integer, &auth_comp_flag,
	  NULL, NULL },
	{ "trace-rules", CS_STMT, NULL, cfg_get_boolean, &auth_trace_rules,
	  NULL, NULL },
	/* Obsolete statements */
	{ "spawn", CS_STMT, NULL, cfg_obsolete, NULL, NULL, NULL },
	{ NULL, }
};

struct cfg_stmt acct_stmt[] = {
	{ "port", CS_STMT, NULL, cfg_get_port, &acct_port, NULL, NULL },
	{ "listen", CS_STMT, NULL, rad_cfg_listen_acct, NULL, NULL, NULL },
	{ "forward", CS_STMT, NULL, rad_cfg_forward_acct, NULL, NULL, NULL },
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
	{ "detail-file-name", CS_STMT, NULL, cfg_get_string,
	  &acct_detail_template, NULL, NULL },
	{ "system", CS_STMT, NULL, cfg_get_boolean, &acct_system,
	  NULL, NULL },
	{ "compare-attribute-flag", CS_STMT, NULL,
	  cfg_get_integer, &acct_comp_flag,
	  NULL, NULL },
	{ "trace-rules", CS_STMT, NULL, cfg_get_boolean, &acct_trace_rules,
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
	{ "option", CS_BLOCK, NULL, NULL, NULL, option_stmt, option_stmt_end },
	{ "message", CS_BLOCK, NULL, NULL, NULL, message_stmt, NULL },
	{ "logging", CS_BLOCK, logging_stmt_begin, logging_stmt_handler, NULL,
	  logging_stmt, logging_stmt_end },
	{ "auth", CS_BLOCK, auth_stmt_begin, NULL, NULL, auth_stmt, NULL },
	{ "acct", CS_BLOCK, acct_stmt_begin, NULL, NULL, acct_stmt, NULL  },
	{ "mlc",  CS_BLOCK, NULL, NULL, NULL, mlc_stmt, NULL },
	{ "proxy", CS_BLOCK, NULL, NULL, NULL, proxy_stmt, NULL  },
	{ "rewrite", CS_BLOCK, rewrite_stmt_term, NULL, NULL, rewrite_stmt, NULL },
	{ "filters", CS_BLOCK, filters_stmt_term, NULL, NULL, filters_stmt,
	  NULL },
	{ "loadable-modules", CS_BLOCK, dynload_stmt_term, NULL, NULL,
	  dynload_stmt, NULL },
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
