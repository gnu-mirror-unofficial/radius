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

/* Socket lists */
struct socket_list {
        struct socket_list *next;
        int fd;
        int (*success)(struct sockaddr *, int);
        int (*respond)(int fd, struct sockaddr *, int, u_char *, int);
        int (*failure)(struct sockaddr *, int);
};

int socket_list_select(struct socket_list *list, struct timeval *tv);
void socket_list_close(struct socket_list *list);
void socket_list_add(struct socket_list **list, int fd,
                     int (*s)(), int (*r)(), int (*f)());

/* Implementation functions */
int auth_respond(int fd, struct sockaddr *sa, int salen,
                 u_char *buf, int size);
int acct_success(struct sockaddr *sa, int salen);
int acct_failure(struct sockaddr *sa, int salen);
int snmp_respond(int fd, struct sockaddr *sa, int salen,
                 u_char *buf, int size);
int radrespond(RADIUS_REQ *radreq, int activefd);

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
struct socket_list *socket_first;

/* Make sure recv_buffer is aligned properly. */
static int i_recv_buffer[RAD_BUFFER_SIZE];
static u_char *recv_buffer = (u_char *)i_recv_buffer;

pthread_t radius_tid;       /* Thread ID of the main thread */
pthread_attr_t thread_attr; /* Attribute for creating child threads */

int max_threads = 128;  /* Maximum number of threads allowed */
int num_threads = 0;    /* Number of threads currently spawned */

#define CMD_NONE    0 /* No command */
#define CMD_RELOAD  1 /* The reload of the configuration is needed */
#define CMD_RESTART 2 /* Try to restart ourselves when set to 1 */
#define CMD_MEMINFO 3 /* Dump memory usage statistics */
#define CMD_DUMPDB  4 /* Dump authentication database */

int daemon_command = CMD_NONE;

static void check_reload();
static void check_snmp_request();

static void set_config_defaults();
void rad_exit(int);
static RETSIGTYPE sig_fatal (int);
static RETSIGTYPE sig_hup (int);
static RETSIGTYPE sig_dumpdb (int);

static int open_socket(UINT4 ipaddr, int port, char *type);
static void open_socket_list(HOSTDECL *hostlist, int defport, char *descr,
                             int (*s)(), int (*r)(), int (*f)());

static void reread_config(int reload);
static void rad_main();
static void meminfo();

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
                radacct_dir = make_string(optarg);
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
                radlog_dir = make_string(optarg);
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
        &rad_common_argp_child,
        NULL, NULL
};

int
main(argc, argv)
        int argc;
        char **argv;
{
        struct servent *svp;
        int t;

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

        srand(time(NULL));
        
        snmp_init(0, 0, emalloc, efree);

        rad_main();
	/*NOTREACHED*/
}

void
set_config_defaults()
{
        config.exec_user  = make_string("daemon");
        username_valid_chars = make_string(".-_!@#$%^&\\/");
        message_text[MSG_ACCOUNT_CLOSED] =
                make_string(_("Sorry, your account is currently closed\n"));
        message_text[MSG_PASSWORD_EXPIRED] =
                make_string(_("Password has expired\n"));
        message_text[MSG_PASSWORD_EXPIRE_WARNING] =
                make_string(_("Password will expire in %R{Password-Expire-Days} Days\n"));
        message_text[MSG_ACCESS_DENIED] =
                make_string(_("\nAccess denied\n"));
        message_text[MSG_REALM_QUOTA] =
                make_string(_("\nRealm quota exceeded - access denied\n"));
        message_text[MSG_MULTIPLE_LOGIN] =
                make_string(_("\nYou are already logged in %R{Simultaneous-Use} times - access denied\n"));
        message_text[MSG_SECOND_LOGIN] =
                make_string(_("\nYou are already logged in - access denied\n"));
        message_text[MSG_TIMESPAN_VIOLATION] =
                make_string(_("You are calling outside your allowed timespan\n"));
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
        signal (SIGHUP, SIG_IGN);

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

        chdir("/");
        umask(022);
        
        pid = getpid();
        p = mkfilename(radpid_dir, "radiusd.pid");
        if ((fp = fopen(p, "w")) != NULL) {
                fprintf(fp, "%d\n", pid);
                fclose(fp);
        }
        efree(p);

        /* Install signal handlers */
        signal(SIGHUP, sig_hup);
        signal(SIGQUIT, sig_fatal);
        signal(SIGTERM, sig_fatal);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGBUS, sig_fatal);
        signal(SIGTRAP, sig_fatal);
        signal(SIGFPE, sig_fatal);
        signal(SIGSEGV, sig_fatal);
        signal(SIGILL, sig_fatal);
        /* Do not handle SIGIOT, please! */
        signal(SIGINT, sig_dumpdb);
        
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
rad_main()
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
                struct timeval tv;

                check_reload();
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                socket_list_select(socket_first, &tv);
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

void
schedule_restart()
{
        daemon_command = CMD_RESTART;
}

/*
 *      Clean up and exit.
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
        case -1:
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

        while (request_flush_list())
                /*nothing:FIXME*/sleep(1);

        return 0;
}

/* Restart RADIUS process
 */
int
rad_restart()
{
        pid_t pid;
        
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
                radlog(L_CRIT|L_PERROR, "fork");
                return -1;
        }

        /* Close all channels we were listening to */
        socket_list_close(socket_first);

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
 *      Read config files.
 */
void
reread_config(reload)
        int reload;
{
        int res = 0;
        
        if (!reload) {
                radlog(L_INFO, _("Starting - reading configuration files ..."));
        } else {
                radlog(L_INFO, _("Reloading configuration files."));
                rad_flush_queues();
                socket_list_close(socket_first);
        }

        socket_first = NULL;
        
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
                socket_list_add(&socket_first, fd, NULL, snmp_respond, NULL);
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
 *      Find out my own IP address (or at least one of them).
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
check_reload()
{
        switch (daemon_command) {
        case CMD_RELOAD:
                radlog(L_INFO, _("Reloading configuration now"));
                reread_config(1);
                break;
        case CMD_RESTART:
                rad_restart();
                break;
        case CMD_MEMINFO:
                meminfo();
                break;
        case CMD_DUMPDB:
                radlog(L_INFO, _("Dumping users db to `%s'"),
                        RADIUS_DUMPDB_NAME);
                dump_users_db();
                break;
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
                        rad_restart();
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
/* Application-specific sockets */

/* Open authentication sockets. */
void
listen_auth(host)
        HOSTDECL *host;
{
        if (radius_mode != MODE_DAEMON)
                return;
        open_socket_list(host, auth_port, "auth", NULL, auth_respond, NULL);
}

/* Open accounting sockets. */
void
listen_acct(host)
        HOSTDECL *host;
{
        if (!open_acct || radius_mode != MODE_DAEMON)
                return;
        open_socket_list(host, acct_port, "acct",
                         acct_success, auth_respond, acct_failure);
}

int
open_socket(ipaddr, port, type)
        UINT4 ipaddr;
        int port;
        char *type;
{
        struct  sockaddr        salocal;
        struct  sockaddr_in     *sin;

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
                socket_list_add(&socket_first, fd, s, r, f);
                return;
        }
        
        for (; hostlist; hostlist = hostlist->next) {
                fd = open_socket(hostlist->ipaddr,
                                 hostlist->port > 0 ? hostlist->port : defport,
                                 descr);
                socket_list_add(&socket_first, fd, s, r, f);
        }
}

/* ************************************************************************* */
/* Signal handling */

static RETSIGTYPE
sig_fatal(sig)
        int sig;
{
        rad_exit(sig);
}

/*ARGSUSED*/
static RETSIGTYPE
sig_hup(sig)
        int sig;
{
        daemon_command = CMD_RELOAD;
        signal(SIGHUP, sig_hup);
}

/*ARGSUSED*/
RETSIGTYPE
sig_dumpdb(sig)
        int sig;
{
        daemon_command = CMD_DUMPDB;
        signal(sig, sig_dumpdb);
}


/* ************************************************************************* */
/* RADIUS request handling functions */

#define REQ_CMP_AUTHENTICATOR 0x01
#define REQ_CMP_CONTENTS      0x02

int
rad_req_cmp(a, b)
        RADIUS_REQ *a, *b;
{
	NAS *nas;
	int cmp = 0;
		
	if (a->ipaddr != b->ipaddr || a->id != b->id)
		return 1;
	
	nas = nas_request_to_nas(a);
	if (!nas)
		cmp = REQ_CMP_AUTHENTICATOR;
	else {
		if (envar_lookup_int(nas->args, "cmpauth", 1))
			cmp |= REQ_CMP_AUTHENTICATOR;
		if (envar_lookup_int(nas->args, "cmppairs", 0))
			cmp |= REQ_CMP_CONTENTS;
	}
	    
	if ((cmp & REQ_CMP_AUTHENTICATOR)
	    && memcmp(a->vector, b->vector, sizeof(a->vector)))
		return 1;

	if ((cmp & REQ_CMP_CONTENTS) && avl_cmp(a->request, b->request))
		return 1;

	return 0;
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
		/* FIXME: resend it too? */
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
        if (radrespond(radreq, fd)) 
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
radrespond(radreq, activefd)
        RADIUS_REQ *radreq;
        int activefd;
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
        memcpy(radreq->data, recv_buffer, radreq->data_len);
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
/* Socket list functions */

void
socket_list_add(list, fd, s, r, f)
        struct socket_list **list;
        int fd;
        int (*s)();
        int (*r)();
        int (*f)();
{
        struct socket_list *ctl;

        ctl = alloc_entry(sizeof(struct socket_list));
        ctl->fd = fd;
        ctl->success = s;
        ctl->respond = r;
        ctl->failure = f;
        ctl->next = *list;
        *list = ctl;
}

void
socket_list_close(list)
        struct socket_list *list;
{
        struct socket_list *next;
        while (list) {
                next = list->next;
                close(list->fd);
                free_entry(list);
                list = next;
        }
}

int
socket_list_select(list, tv)
        struct socket_list *list;
        struct timeval *tv;
{
        int result;
        int status;
        int salen;
        struct sockaddr saremote;
        fd_set readfds;
        struct socket_list *ctl;
        int max_fd = 0;

        FD_ZERO(&readfds);
        for (ctl = list; ctl; ctl = ctl->next) {
                FD_SET(ctl->fd, &readfds);
                if (ctl->fd > max_fd)
                        max_fd = ctl->fd;
        }

        debug(100,("selecting (%d fds)", max_fd+1));
        status = select(max_fd + 1, &readfds, NULL, NULL, tv);
        
        if (status == -1) {
                if (errno == EINTR) 
                        return 0;
                return -1;
        } else if (status == 0) 
                return 0;
        debug(100,("processing..."));
        for (ctl = list; ctl; ctl = ctl->next) {
                if (FD_ISSET(ctl->fd, &readfds)) {
                        salen = sizeof (saremote);
                        result = recvfrom (ctl->fd, (char *) recv_buffer,
                                               (int) sizeof(i_recv_buffer),
                                               (int) 0, &saremote, &salen);

                        if (ctl->success)
                                ctl->success(&saremote, salen);
                        if (result > 0) {
                                debug(100,("calling respond"));
                                ctl->respond(ctl->fd,
                                             &saremote, salen,
                                             recv_buffer, result);
                                debug(100,("finished respond"));
                        } else if (result < 0 && errno == EINTR) {
                                if (ctl->failure)
                                        ctl->failure(&saremote, salen);
                                result = 0;
                        }
                }
        }
        return 0;
}


