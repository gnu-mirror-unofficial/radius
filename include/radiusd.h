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

#include <sysdep.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <pthread.h>
#include <radius.h>
#include <radpaths.h>
#include <signal.h>
#include <cfg.h>

/* Debugging macros */
#define Pthread_mutex_lock(m) \
 do { \
      debug(100,("locking " #m)); \
      pthread_mutex_lock(m);\
      debug(100,("locked " #m)); \
 } while (0)

#define Pthread_mutex_unlock(m) \
 do { \
      debug(100,("unlocking " #m)); \
      pthread_mutex_unlock(m);\
      debug(100,("unlocked " #m)); \
 } while (0)

/* Server data structures */
struct radutmp; /* declared in radutmp.h */
struct obstack;

enum reload_what {
        reload_config,
        reload_all,
        reload_dict,
        reload_users,
        reload_huntgroups,
        reload_hints,
        reload_clients, 
        reload_naslist, 
        reload_realms,
        reload_deny,
        reload_sql,
        reload_rewrite
};

/* ********************** Request list handling **************************** */

/* Request types
 */
#define R_NONE -1
#define R_AUTH  0        /* Radius authentication request */
#define R_ACCT  1        /* Radius accounting request */
#define R_PROXY 2        /* Radius auth/acct proxy request */
#define R_SNMP  3        /* SNMP request */
#define R_MAX   4

/* Request class structure
 */
typedef struct request_class {
        char *name;           /* Class name */
        int  max_requests;    /* Max.number of pending requests of this type */
        int  ttl;             /* Request time-to-live */
        int  cleanup_delay;   /* Delay before cleaning the completed request */
        int  (*setup)();      /* Setup function */
        int  (*handler)();    /* Handler function */
        void (*xmit)();       /* Retransmit function */
        int  (*comp)();       /* Compare function */
        void (*free)();       /* Free */
        void (*drop)();       /* Drop request error message */
        void (*cleanup)();    /* Cleanup function */
} REQUEST_CLASS;

typedef struct socket_list SOCKET_LIST;
struct request_handler_tab {
        int (*success)(struct sockaddr *, int);
        int (*respond)(int fd, struct sockaddr *, int, u_char *, int);
        int (*failure)(struct sockaddr *, int);
};

#define RS_WAITING   0     /* Request waiting for processing */
#define RS_PENDING   1     /* Request is being processed */
#define RS_COMPLETED 2     /* Request is completed */
#define RS_HUNG      3     /* Request is (possibly) hung */
#define RS_DEAD      4     /* Request was killed */

typedef struct request {
        struct request *next;         /* Link to the next request */
        int             type;         /* request type */
        int             status;       /* request status */
        time_t          timestamp;    /* when was the request accepted */
        pthread_t       child_id;     /* ID of the handling process (or -1) */
        int             child_return; /* Child return code if completed */
        void           *data;         /* Request-specific data */
        int             fd;           /* socket the request came from */
} REQUEST;

struct queue_stat {
        size_t waiting;
        size_t pending;
        size_t completed;
};
typedef struct queue_stat QUEUE_STAT[R_MAX];
        
typedef struct client {
        struct client           *next;
        UINT4                   ipaddr;
        char                    longname[MAX_LONGNAME+1];
        u_char                  *secret;
        char                    shortname[MAX_SHORTNAME+1];
} CLIENT;

typedef struct proxy_id {
        struct proxy_id         *next;
        UINT4                   ipaddr;
        u_char                  id;
} PROXY_ID;

typedef struct proxy_state {
        UINT4                   ipaddr;
        UINT4                   id;
        UINT4                   proxy_id;
        UINT4                   rem_ipaddr;
} PROXY_STATE;

/*
 * Internal representation of a user's profile
 */
typedef struct user_symbol {
        struct user_symbol *next;
        char *name;
        int lineno;
        int ordnum;
        VALUE_PAIR *check;
        VALUE_PAIR *reply;
} User_symbol;

#define SNMP_RO 1
#define SNMP_RW 2

#ifdef USE_SNMP

#include <radsnmp.h>

typedef struct community_list Community;
struct community_list {
        Community *next;
        char *name;
        int access;
} ;

typedef struct access_control_list ACL;
struct access_control_list {
        ACL *next;           /* next ACL */
        Community *community;/* community or NULL to deny access */
        UINT4 ipaddr;        /* IP address */
        UINT4 netmask;
};

struct radstat {
        struct timeval start_time;
        counter port_active_count;
        counter port_idle_count;
};

typedef enum {
        port_idle = 1,
        port_active
} port_status;

typedef struct {
        struct timeval start_time;
        unsigned port_count; /* Number of ports in the port_stat array */
        unsigned nas_count;  /* Number of NASes in the nas_stat array */
        int nas_index; /* Next available NAS index */
        Auth_server_stat auth;
        Acct_server_stat acct;
        struct nas_stat *nas_head, *nas_tail;
        struct port_stat *port_head, *port_tail;
} Server_stat;

#define stat_inc(m,a,c) \
 do {\
        NAS *nas;\
        server_stat . ##m . ##c ++;\
        if ((nas = nas_lookup_ip(a)) != NULL && nas->app_data)\
                ((struct nas_stat*)nas->app_data)-> ##m . ##c ++;\
 } while (0)

extern struct radstat radstat;

typedef struct snmp_req {
        struct snmp_pdu *pdu;
        char *community;
        int access;
        struct sockaddr_in sa;
        int fd;
} SNMP_REQ;

#else
#define stat_inc(m,a,c)
#endif

typedef void (*config_hook_fp)(void *func_data, void *app_data);

#define SECONDS_PER_DAY         86400
#define MAX_REQUEST_TIME        60
#define CLEANUP_DELAY           10
#define MAX_REQUESTS            255


/*
 * Authentication results
 */
#define AUTH_OK      0 /* OK */
#define AUTH_FAIL    1 /* Password fail */
#define AUTH_NOUSER  2 /* No such user  */
#define AUTH_REJECT  3 /* Rejected */
#define AUTH_IGNORE  4 /* Silently ignore */

/* Logging modes */
#define RLOG_AUTH               0x0001
#define RLOG_AUTH_PASS          0x0002
#define RLOG_FAILED_PASS        0x0004
#define RLOG_DEFAULT            (RLOG_AUTH | RLOG_FAILED_PASS)

/* Running modes */
#define MODE_DAEMON    0
#define MODE_CHECKCONF 1
#define MODE_TEST      2
#define MODE_BUILDDBM  3

/* Message IDs */
#define MSG_ACCOUNT_CLOSED          0
#define MSG_PASSWORD_EXPIRED        1
#define MSG_PASSWORD_EXPIRE_WARNING 2
#define MSG_ACCESS_DENIED           3
#define MSG_REALM_QUOTA             4
#define MSG_MULTIPLE_LOGIN          5
#define MSG_SECOND_LOGIN            6
#define MSG_TIMESPAN_VIOLATION      7
#define MSG_COUNT                   8

/*
 *      Global variables.
 */
extern SOCKET_LIST *socket_first;
extern int radius_mode;
extern int debug_flag;
extern int auth_detail;
extern int acct_detail;
extern int strip_names;
extern int checkrad_assume_logged;
extern int max_requests;
extern char *exec_user;
extern UINT4 expiration_seconds;
extern UINT4 warning_seconds;
extern int use_dbm;
extern UINT4 myip;
extern int auth_port;
extern int acct_port;
extern int suspend_flag;
extern int log_mode;
extern int use_guile;
extern char *message_text[MSG_COUNT];
extern char *username_valid_chars;
extern unsigned long stat_start_time;
extern REQUEST_CLASS    request_class[];
extern pthread_attr_t thread_attr;
extern int max_threads;
extern int num_threads;
#ifdef USE_SERVER_GUILE
extern unsigned scheme_gc_interval;
extern u_int scheme_task_timeout;
#endif
#ifdef USE_SNMP
extern int snmp_port;
extern char *server_id;
extern Server_stat server_stat;
extern struct cfg_stmt snmp_stmt[];
#endif

/*
 *      Function prototypes.
 */

/* acct.c */
int rad_accounting(RADIUS_REQ *, int);
int radzap(UINT4 nas, int port, char *user, time_t t);
int rad_check_multi(char *name, VALUE_PAIR *request, int maxsimul, int *pcount);
int rad_check_realm(REALM *realm);
int write_detail(RADIUS_REQ *radreq, int authtype, char *f);

/* radiusd.c */
int stat_request_list(QUEUE_STAT);
void *scan_request_list(int type, int (*handler)(), void *closure);
int set_nonblocking(int fd);
void radiusd_thread_init();
int radiusd_flush_queues();
void schedule_restart();
void radiusd_mainloop();
void rad_req_drop(int type, RADIUS_REQ *req, RADIUS_REQ *orig, int fd,
		  char *status_str);
int radiusd_mutex_lock(pthread_mutex_t *mutex, int type);
int radiusd_mutex_unlock(pthread_mutex_t *mutex);
void radiusd_pidfile_write(char *name);
pid_t radiusd_pidfile_read(char *name);
void radiusd_pidfile_remove(char *name);
int radiusd_is_watched();
int radiusd_restart();
int radiusd_primitive_restart();
void run_before_config_hooks(void *data);
void run_after_config_hooks(void *data);
void register_before_config_hook(config_hook_fp fp, void *data);
void register_after_config_hook(config_hook_fp fp, void *data);

/* radius.c */

#define REQ_AUTH_OK   0
#define REQ_AUTH_ZERO 1
#define REQ_AUTH_BAD  2

void rad_send_reply(int, RADIUS_REQ *, VALUE_PAIR *, char *, int);
RADIUS_REQ *radrecv (UINT4, u_short, u_char *, int);
int validate_client(RADIUS_REQ *radreq);
int calc_acctdigest(RADIUS_REQ *radreq);
void send_challenge(RADIUS_REQ *radreq, char *msg, char *state, int activefd);


/* files.c */
int user_find(char *name, RADIUS_REQ *, VALUE_PAIR **, VALUE_PAIR **);
int userparse(char *buf, VALUE_PAIR **first_pair, char **errmsg);
void presuf_setup(VALUE_PAIR *request_pairs);
int hints_setup(RADIUS_REQ *request);
int huntgroup_access(RADIUS_REQ *radreq);
CLIENT *client_lookup_ip(UINT4 ipno);
char *client_lookup_name(UINT4 ipno, char *buf, size_t size);
int read_clients_file(char *);
NAS *nas_find(UINT4 ipno);
NAS *nas_by_name(char *name);
char *nas_name(UINT4 ipno);
char *nas_name2(RADIUS_REQ *r);
int read_naslist_file(char *);
int reload_config_file(enum reload_what);
int presufcmp(VALUE_PAIR *check, char *name, char *rest);
int get_config();
int get_deny(char *user);
NAS *findnasbyindex(int);
char *make_server_ident();
void dump_users_db();
void strip_username(int do_strip, char *name,
                    VALUE_PAIR *check_item, char *stripped_name);

/* version.c */
void version();


/* pam.c */
#ifdef USE_PAM
int pam_pass(char *name, char *passwd, const char *pamauth, char **reply_msg);
# define PAM_DEFAULT_TYPE    "radius"
#endif

/* proxy.c */
int rad_proxy(RADIUS_REQ *radreq, int activefd);
void rad_proxy_free(RADIUS_REQ *req);
int proxy_send(RADIUS_REQ *radreq, int activefd);
int proxy_receive(RADIUS_REQ *radreq, int activefd);
void proxy_retry(int type, RADIUS_REQ *radreq, RADIUS_REQ *orig_req,
		int fd, char *status_str);

void proxy_cleanup();

/* auth.c */
int rad_auth_init(RADIUS_REQ *radreq, int activefd);
int rad_authenticate (RADIUS_REQ *, int);
void req_decrypt_password(char *password, RADIUS_REQ *req, VALUE_PAIR *pair);

/* exec.c */
int radius_exec_program(char *, RADIUS_REQ *, VALUE_PAIR **,
                        int, char **user_msg);
void filter_cleanup();
int filter_auth(char *name, RADIUS_REQ *req, VALUE_PAIR **reply_pairs);
int filter_acct(char *name, RADIUS_REQ *req);
int filters_stmt_term(int finish, void *block_data, void *handler_data);
extern struct cfg_stmt filters_stmt[];

/* menu.c */
void process_menu(RADIUS_REQ *radreq, int fd);
char * get_menu(char *menu_name);


#define MAX_PATH_LENGTH                 256
#define MAX_MENU_SIZE                   4096
#define MAX_MENU_NAME                   128
#define MAX_MENU_INPUT                  32
#define MAX_STATE_VALUE                 128
#define RAD_BUFFER_SIZE                 4096


/* timestr.c */
int timestr_match(char *, time_t);

#ifdef USE_SNMP
/* snmpserv.c */
void snmpserv_init(void *arg);
void snmp_auth_server_reset();
void snmp_acct_server_reset();
void snmp_attach_nas_stat(NAS *nas);
void snmp_init_nas_stat();
int check_acl(UINT4 ipaddr, char *community);
void snmp_free_acl();
void free_acl(ACL *);
void snmp_add_acl(ACL *, Community *);
Community * snmp_find_community(char *);
void snmp_add_community(char *str, int access);
void snmp_free_communities();
void snmp_sort_nas_stat();
int snmp_stmt_begin(int finish, void *data, void *up_data);
#endif

/* stat.c */
#ifdef USE_SNMP
void stat_init();
void stat_done();
void stat_update(struct radutmp *ut, int status);
void stat_count_ports();
struct nas_stat * find_nas_stat(UINT4 ip_addr);
int stat_get_port_index(NAS *nas, int port_no);
int stat_get_next_port_no(NAS *nas, int port_no);
#else
# define stat_init()
# define stat_done()
# define stat_update(ut,status)
#endif

/* snmpserver.c */
struct sockaddr_in;
struct snmp_req * rad_snmp_respond(u_char *buf, int len,
                                   struct sockaddr_in *sa);
int snmp_req_cmp(struct snmp_req *a, struct snmp_req *b);
void snmp_req_free(struct snmp_req  *req);
void snmp_req_drop(int type, struct snmp_req *req, struct snmp_req *orig_req,
		   int fd, char *status_str);
int snmp_answer(struct snmp_req *req, int fd);
        
/* radutil.c */
char *radius_xlate(struct obstack *obp, char *str,
                   RADIUS_REQ *req, VALUE_PAIR *reply_pairs);

/* log.c */
void sqllog __PVAR((int status, char *msg, ...));
int logging_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
			 void *handler_data);
int logging_stmt_end(void *block_data, void *handler_data);
int logging_stmt_begin(int finish, void *block_data, void *handler_data);
extern struct cfg_stmt logging_stmt[];

/* rewrite.y */
extern struct cfg_stmt rewrite_stmt[];
int run_rewrite(char *name, RADIUS_REQ *req);
int parse_rewrite(char *name);
int va_run_init __PVAR((char *name, RADIUS_REQ *request, char *typestr, ...));

/* radck.c */
int fix_check_pairs(int sf_file, char *filename, int line, char *name,
                    VALUE_PAIR **pairs);
int fix_reply_pairs(int cf_file, char *filename, int line, char *name,
                    VALUE_PAIR **pairs);
void radck();

/* scheme.c */
void rad_boot();
void scheme_load(char *filename);
void scheme_load_path(char *pathname);
void scheme_debug(int val);
int scheme_auth(char *procname, RADIUS_REQ *req,
                VALUE_PAIR *user_check, VALUE_PAIR **user_reply_ptr);
int scheme_acct(char *procname, RADIUS_REQ *req);
void scheme_add_load_path(char *path);
void scheme_read_eval_loop();
void start_guile();
int guile_cfg_handler(int argc, cfg_value_t *argv,
		      void *block_data, void *handler_data);
extern struct cfg_stmt guile_stmt[];

/* request.c */
typedef void (*request_thread_command_fp)(void *);

int request_start_thread();
void request_signal();
REQUEST *request_put(int type, void *data, int fd, unsigned *numpending);
REQUEST *request_get();
int request_flush_list();
int request_stat_list(QUEUE_STAT stat);
void request_handle(REQUEST *req);
void *request_scan_list(int type, int (*handler)(), void *closure);
void request_thread_command(request_thread_command_fp fun, void *data);


/* checkrad.c */
int checkrad(NAS *nas, struct radutmp *up);

/* socklist.c */
int socket_list_add(SOCKET_LIST **slist, int type, UINT4 ipaddr, int port);
void socket_list_init(SOCKET_LIST *slist);
int socket_list_open(SOCKET_LIST **slist);
int socket_list_select(struct socket_list *list,
		       struct request_handler_tab *ht,
		       size_t numh,
		       struct timeval *tv);
void socket_list_close(SOCKET_LIST **slist);
void socket_list_iterate(SOCKET_LIST *slist, void (*fun)());

/* signal.c */
#define SH_SYNC  0
#define SH_ASYNC 1
#define SH_DELETED 2

typedef void *rad_sigid_t;
typedef int (*rad_signal_t) (int sig, void *data, rad_sigid_t id,
			     const void *owner);

rad_sigid_t rad_signal_install (int sig, int type,
				rad_signal_t handler, void *data);
rad_sigid_t rad_signal_remove (int sig, rad_sigid_t id, const void *owner);


