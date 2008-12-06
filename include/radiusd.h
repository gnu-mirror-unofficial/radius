/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007,2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>

#include <common.h>
#include <cfg.h>
#include <radsql.h>

/* Server data structures */
struct radutmp; /* declared in radutmp.h */

/* Struct radiusd_request expands grad_request_t by adding server-specific
   fields to it. */
typedef struct radiusd_request {
	grad_request_t *request;
	
        /* Saved reply values */
        int           reply_code;   /* Reply code */
        grad_avp_t    *reply_pairs; /* Reply pairs */
        char          *reply_msg;   /* Reply message */
	                            /* FIXME: should probably be
			 	       incorporated to reply_pairs
				       at once */
	/* List of cfg file locations that lead to the decision on this
	   request */
	grad_list_t   *locus_list;
	
        /* Proxy support fields */
        grad_realm_t  *realm;       
        int           validated;     /* Already md5 checked */
	int           server_no;
	int           attempt_no;
        grad_uint32_t server_id;     /* Proxy ID of the packet */
	char          *remote_user;  /* Remote username */
        u_char        remote_auth[GRAD_AUTHENTICATOR_LENGTH];
	                             /* Remote request authenticator */	
        int           server_code;   /* Reply code from other srv */
        grad_avp_t    *server_reply; /* Reply from other server */
} radiusd_request_t;

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
#define R_SNMP  2        /* SNMP request */
#define R_MAX   3

#define RS_WAITING    0     /* Request waiting for processing */
#define RS_COMPLETED  1     /* Request is completed */
#define RS_PROXY      2     /* Proxy request waiting for its handler
			       to become free */
#define RS_XMIT       3     /* The request is to be retransmitted to its
			       handler and is waiting for it to
			       become free */
#define RS_TERMINATED 4     /* TERM has been sent to the handler */
			      
/* Request comparison results */
#define RCMP_NE     0      /* Requests not equal */
#define RCMP_EQ     1      /* Requests equal */
#define RCMP_PROXY  2      /* Requests are proxy request and corresponding
			      reply */
typedef struct request REQUEST;

struct request {
        int             type;         /* request type */
        int             status;       /* request status */
        time_t          timestamp;    /* when was the request accepted */
        pid_t           child_id;     /* ID of the handling process */
        int             code;         /* Child return code if completed */
        void            *data;        /* Request-specific data */
	void            *rawdata;     /* Raw data as received from the
					 socket */  
	size_t          rawsize;      /* Size of the data */
        int             fd;           /* socket the request came from */
	struct sockaddr_in srv_addr;  /* Server address */
	struct sockaddr_in addr;      /* Remote party address */
	REQUEST         *orig;        /* Original request. For proxy */
};

/* Request class structure
 */
typedef struct request_class {
        char *name;           /* Class name */
        int  max_requests;    /* Max.number of pending requests of this type */
        int  ttl;             /* Request time-to-live */
        int  cleanup_delay;   /* Delay before cleaning the completed request */
	int  (*decode)(const struct sockaddr_in *srv_sa,
		       const struct sockaddr_in *clt_sa,
		       void *input, size_t inputsize, void **output);
        int  (*respond)(REQUEST *r);          /* Handler function */
        void (*xmit)(REQUEST *r);             /* Retransmit function */
        int  (*comp)(void *a, void *b);       /* Compare function */
        void (*free)(void *data);             /* Free the associated data */
        void (*drop)(int type, void *data, void *old_data, int fd,
		     const char *msg);        /* Drop the request */
        void (*cleanup)(int type, void *data);/* Cleanup function */
        int (*failure)(int type, struct sockaddr_in *addr);
	void (*update)(void *req, void *ptr);
} REQUEST_CLASS;

struct queue_stat {
        size_t waiting;
        size_t pending;
        size_t completed;
};
typedef struct queue_stat QUEUE_STAT[R_MAX];

typedef struct client {
	grad_netdef_t           netdef;
        char                    longname[GRAD_MAX_LONGNAME+1];
        u_char                  *secret;
        char                    shortname[GRAD_MAX_SHORTNAME+1];
} CLIENT;

typedef struct proxy_state {
	grad_uint32_t ref_ip;             /* Radius server IP */
        grad_uint32_t proxy_id;           /* Proxy ID assigned by the server */
        grad_uint32_t remote_ip;          /* Remote radius server IP */
        grad_uint32_t client_ip;          /* IP of the requesting client */ 
        grad_uint32_t id;                 /* Radius request ID */
} PROXY_STATE;

typedef struct {
	int id;
	int proxy_id;
	int server_no;
	char realmname[1];
} RADIUS_UPDATE;

/*
 * Internal representation of a user's profile
 */
typedef struct user_symbol {
        struct user_symbol *next;  /* Link to the next entry */
        char *name;                /* Label */
        grad_avp_t *check;         /* LHS */
        grad_avp_t *reply;         /* RHS */
        grad_locus_t loc;                 /* Location of the definition of
				      this entry */
        int ordnum;                /* Entry ordinal number (used for semantic
				      checks */
} User_symbol;

#define SNMP_RO 1
#define SNMP_RW 2

#ifdef USE_SNMP

#include <radsnmp.h>

typedef struct netname NETNAME;
struct netname {
	char *name;
	grad_list_t /* of grad_netdef_t */ *netlist;
};

typedef struct community Community;
struct community {
        char *name;
        int access;
} ;

typedef struct access_control_list ACL;
struct access_control_list {
        Community *community;   /* community or NULL to deny access */
	grad_list_t /* of grad_netdef_t */ *netlist;
};

struct radstat {
        struct timeval start_time;
        grad_counter_t port_active_count;
        grad_counter_t port_idle_count;
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
        /* struct nas_stat naslist[nas_count];
	   struct port_stat portlist[port_count]; */
} Server_stat;

#define stat_inc(m,a,c) \
 do if (server_stat) {\
        grad_nas_t *nas;\
        server_stat -> m . c ++;\
        if ((nas = grad_nas_lookup_ip(a)) != NULL && nas->app_data)\
                ((struct nas_stat*)nas->app_data)-> m . c ++;\
 } while (0)

extern struct radstat radstat;

typedef struct snmp_req {
        struct snmp_pdu *pdu;
        char *community;
        int access;
	struct sockaddr_in addr;
} SNMP_REQ;

#else
#define stat_inc(m,a,c)
#endif

typedef void (*config_hook_fp)(void *func_data, void *app_data);

#define SECONDS_PER_DAY         86400
#define MAX_REQUEST_TIME        60
#define CLEANUP_DELAY           10
#define MAX_REQUESTS            255
#define MAX_CHILDREN            16
#define PROCESS_TIMEOUT         3600
#define RADIUSD_READ_TIMEOUT    5
#define RADIUSD_WRITE_TIMEOUT   5

/*
 * Authentication results
 */
enum auth_status {
	auth_ok,              /* Authentication passed */
	auth_valid,           /* Authentication passed, expiration timeout
				 is returned */
	auth_account_expired, /* Account has expired */
	auth_password_expired,/* Password has expired */ 
	auth_fail,
	auth_nouser,
	auth_reject,
	auth_ignore,
};

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

typedef struct radiusd_user {
	char *username;
	uid_t uid;
	gid_t gid;
} RADIUS_USER;

/*
 *      Global variables.
 */
extern int radius_mode;
extern int debug_flag;
extern int auth_detail;
extern int acct_detail;
extern char *auth_detail_template;
extern char *acct_detail_template;
extern int acct_system;
extern int auth_trace_rules;
extern int acct_trace_rules;
extern int strip_names;
extern int checkrad_assume_logged;
extern int auth_reject_malformed_names;
extern size_t max_requests;
extern size_t max_children;
extern unsigned process_timeout;
extern unsigned radiusd_write_timeout;
extern unsigned radiusd_read_timeout;
extern grad_uint32_t expiration_seconds;
extern grad_uint32_t warning_seconds;
extern int use_dbm;
extern grad_uint32_t myip;
extern grad_uint32_t ref_ip;
extern int auth_port;
extern int acct_port;
extern int suspend_flag;
extern int log_mode;
extern char *auth_log_hook;
extern int use_guile;
extern char *message_text[MSG_COUNT];
extern char *username_valid_chars;
extern unsigned long stat_start_time;
extern REQUEST_CLASS    request_class[];
extern int max_threads;
extern int num_threads;
#ifdef USE_SNMP
extern int snmp_port;
extern char *server_id;
extern Server_stat *server_stat;
extern struct cfg_stmt snmp_stmt[];
#endif
extern int auth_comp_flag; 
extern int acct_comp_flag; 
extern RADIUS_USER exec_user;
extern RADIUS_USER radiusd_user;
extern grad_symtab_t *user_tab;

/* Input subsystem (input.c) */

typedef struct input_system INPUT;

INPUT *input_create();
void input_register_method(INPUT *input,
			   const char *name,
			   int prio,
			   int (*handler)(int, void *),
			   int (*close)(int, void *),
			   int (*cmp)(const void *, const void *));
int input_register_channel(INPUT *input, char *name, int fd, void *data);
void input_close_channels(INPUT *input);
void input_close_channel_fd(INPUT *input, int fd);
void input_close_channel_data(INPUT *input, char *name, void *data); 
int input_select(INPUT *input, struct timeval *tv);
int input_select_channel(INPUT *input, char *name, struct timeval *tv);
void *input_find_channel(INPUT *input, char *name, void *data);
void input_iterate_channels(INPUT *input, char *name, list_iterator_t fun,
			    void *data);

/* rpp.c */
int rpp_ready();
int rpp_forward_request(REQUEST *req);
void rpp_remove_pid(pid_t pid);
void rpp_status_changed(pid_t pid, int exit_status);
void rpp_flush(int (*fun)(void*), void *closure);
void rpp_collect_exited();
int rpp_input_handler(int fd, void *data);
int rpp_input_close(int fd, void *data);
int rpp_kill(pid_t pid, int signo);
size_t rpp_count();
int rpp_update(void *data, size_t size);
pid_t rpp_check_pid(pid_t pid);

/* request.c */
REQUEST *request_create(int type, int fd,
			const struct sockaddr_in *srv_sa,
			const struct sockaddr_in *clt_sa,
			u_char *buf, size_t bufsize);
void request_free(REQUEST *req);
int request_respond(REQUEST *req);
int request_handle(REQUEST *req, int (*handler)(REQUEST *));
void request_fail(int type, struct sockaddr_in *addr);
void request_init_queue();
void *request_scan_list(int type, list_iterator_t itr, void *closure);
void request_set_status(pid_t pid, int status);
int request_stat_list(QUEUE_STAT stat);
void request_update(pid_t pid, int status, void *ptr);

/* radiusd.c */
int udp_input_handler(int fd, void *data);
int udp_input_close(int fd, void *data);
int udp_input_cmp(const void *a, const void *b);

int udp_open(int type, grad_uint32_t ipaddr, int port, int nonblock);

void radiusd_pidfile_write(char *name);
pid_t radiusd_pidfile_read(char *name);
void radiusd_pidfile_remove(char *name);

void radiusd_main();
void radiusd_signal_init(RETSIGTYPE (*)(int));
void radiusd_cleanup();
void radiusd_restart();
void radiusd_flush_queue();
void radiusd_exit();
void radiusd_exit0();
void radiusd_reconfigure();
int radiusd_master();
void radiusd_set_preconfig_hook(void (*f)(void *, void *), void *p, int once);
void radiusd_set_postconfig_hook(void (*f)(void *, void *), void *p, int once);
void radiusd_register_input_fd(char *name, int fd, void *data);
void radiusd_close_channel(int fd);

/* exec.c */
int radius_get_user_ids(RADIUS_USER *usr, const char *name);
int radius_switch_to_user(RADIUS_USER *usr);
int radius_exec_command(char *cmd);
int radius_exec_program(char *, radiusd_request_t *, grad_avp_t **, int);
void filter_cleanup(pid_t pid, int status);
int filter_auth(char *name, radiusd_request_t *req, grad_avp_t **reply_pairs);
int filter_acct(char *name, radiusd_request_t *req);
int filters_stmt_term(int finish, void *block_data, void *handler_data);
extern struct cfg_stmt filters_stmt[];

/* scheme.c */
void scheme_main();
void scheme_load_path(char *pathname);
int scheme_auth(char *procname, radiusd_request_t *req,
                grad_avp_t *user_check, grad_avp_t **user_reply_ptr);
int scheme_acct(char *procname, radiusd_request_t *req);
int scheme_eval_boolean_expr(char *expr);
int scheme_eval_avl (radiusd_request_t *request,
		     grad_avp_t *lhs, grad_avp_t *rhs,
		     grad_avp_t **reply,
		     grad_avp_t **pfailed);
void scheme_eval_unspecified_expr(char *expr);
void scheme_read_eval_loop();
void scheme_redirect_output();
void start_guile();

int guile_cfg_handler(int argc, cfg_value_t *argv,
		      void *block_data, void *handler_data);
extern struct cfg_stmt guile_stmt[];

/* log.c */
void radiusd_logger(int level,
		    const grad_request_t *req,
		    const grad_locus_t *loc,
		    const char *func_name,
		    int en,
		    const char *fmt, va_list ap);
void sqllog(int status, char *query);
int logging_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
			 void *handler_data);
int logging_stmt_end(void *block_data, void *handler_data);
int logging_stmt_begin(int finish, void *block_data, void *handler_data);
void format_exit_status(char *buffer, int buflen, int status);
int log_change_owner(RADIUS_USER *usr);
extern struct cfg_stmt logging_stmt[];

/* radius.c */

#define REQ_AUTH_OK   0
#define REQ_AUTH_ZERO 1
#define REQ_AUTH_BAD  2

void radius_send_reply(int, radiusd_request_t *, grad_avp_t *, char *, int);
void radius_send_challenge(radiusd_request_t *radreq, char *msg, char *state, int fd);
int radius_verify_digest(REQUEST *req);

int radius_auth_req_decode(const struct sockaddr_in *srv_sa,
			   const struct sockaddr_in *clt_sa,
			   void *input, size_t inputsize, void **output);
int radius_acct_req_decode(const struct sockaddr_in *srv_sa,
			   const struct sockaddr_in *clt_sa,
			   void *input, size_t inputsize, void **output);
int radius_req_cmp(void *a, void *b);
void radius_req_free(void *req);
void radius_req_drop(int type, void *radreq, void *origreq,
		     int fd, const char *status_str);
void radius_req_xmit(REQUEST *request);
int radius_req_failure(int type, struct sockaddr_in *addr);
void radius_req_update(void *req_ptr, void *data_ptr);
int radius_respond(REQUEST *req);
void radius_req_register_locus(radiusd_request_t *req, grad_locus_t *loc);
void radius_trace_path(radiusd_request_t *req);
grad_avp_t *radius_decrypt_request_pairs(radiusd_request_t *req, grad_avp_t *pair);
void radius_destroy_pairs(grad_avp_t **p);

/* shmem.c */
int shmem_alloc(size_t size);
void shmem_free();
void *shmem_get(size_t size, int zero);

/* pam.c */
int pam_pass(char *name, char *passwd, const char *pamauth, char **reply_msg);
#define PAM_DEFAULT_TYPE    "radius"

/* proxy.c */
int proxy_send(REQUEST *req);
int proxy_receive(radiusd_request_t *radreq, radiusd_request_t *oldreq, int activefd);
void proxy_retry(radiusd_request_t *radreq, int fd);
int proxy_cmp(radiusd_request_t *qr, radiusd_request_t *r);
grad_avp_t *proxy_request_recode(radiusd_request_t *radreq, grad_avp_t *plist,
				 u_char *secret, u_char *authenticator);

/* menu.c */
#define MAX_PATH_LENGTH                 256
#define MAX_MENU_SIZE                   4096
#define MAX_MENU_NAME                   128
#define MAX_MENU_INPUT                  32
#define MAX_STATE_VALUE                 128
#define RAD_BUFFER_SIZE                 4096

void menu_reply(radiusd_request_t *radreq, int fd);
char *menu_read_text(char *menu_name);

/* acct.c */
void system_acct_init();
void acct_init();
int rad_accounting(radiusd_request_t *, int, int);
int radzap(grad_uint32_t nas, int port, char *user, time_t t);
int write_detail(radiusd_request_t *radreq, int authtype, int rtype);

int radutmp_mlc_collect_user(char *name, radiusd_request_t *request,
			     grad_list_t **sess_list);
int radutmp_mlc_collect_realm(radiusd_request_t *request,
			      grad_list_t **sess_list);
void radutmp_mlc_close(struct radutmp *up);
int radutmp_mlc_enabled_p(void);

/* mlc.c */
typedef int (*mlc_collect_user_t) (char *name, radiusd_request_t *request,
				   grad_list_t **sess_list);
typedef int (*mlc_collect_realm_t) (radiusd_request_t *request,
				    grad_list_t **sess_list);
typedef void (*mlc_close_t) (struct radutmp *up);
typedef int (*mlc_enabled_t) (void);
void mlc_register_method(char *name,
			 mlc_collect_user_t collect_user,
			 mlc_collect_realm_t collect_realm,
			 mlc_close_t close,
			 mlc_enabled_t enabled_p);

extern struct cfg_stmt mlc_stmt[];
int radius_mlc_user(char *name, radiusd_request_t *request,
		    size_t maxsimul, size_t *pcount);
int radius_mlc_realm(radiusd_request_t *request);

/* files.c */
int user_find(char *name, radiusd_request_t *, grad_avp_t **, grad_avp_t **);
int userparse(char *buf, grad_avp_t **first_pair, char **errmsg);
void presuf_setup(grad_avp_t *request_pairs);
int hints_setup(radiusd_request_t *request);
int huntgroup_access(radiusd_request_t *radreq, grad_locus_t *loc);
CLIENT *client_lookup_ip(grad_uint32_t ipno);
char *client_lookup_name(grad_uint32_t ipno, char *buf, size_t size);
int read_clients_file(char *);
grad_nas_t *grad_nas_find(grad_uint32_t ipno);
grad_nas_t *grad_nas_by_name(char *name);
char *grad_nas_name(grad_uint32_t ipno);
char *nas_name2(radiusd_request_t *r);
int read_nas_list_file(char *);
int reload_config_file(enum reload_what);
int presufcmp(grad_avp_t *check, char *name, char *rest);
int get_config();
int get_deny(char *user);
grad_nas_t *findnasbyindex(int);
char *make_server_ident();
void dump_users_db();
void strip_username(int do_strip, char *name,
                    grad_avp_t *check_item, char *stripped_name);
int exec_program_wait (radiusd_request_t *request, grad_avp_t *rhs,
		       grad_avp_t **reply, grad_avp_t **pfailed);

/* version.c */
void version();

/* auth.c */
int rad_auth_init(radiusd_request_t *radreq, int activefd);
int rad_auth_check_username(radiusd_request_t *radreq, int activefd);
int rad_authenticate (radiusd_request_t *, int);
void req_decrypt_password(char *password, grad_request_t *req,
			  grad_avp_t *pair);

/* timestr.c */
int timestr_match(char *, time_t);

#ifdef USE_SNMP
/* snmpserv.c */
void snmpserv_init(void *arg);
void snmp_auth_server_reset();
void snmp_acct_server_reset();
void snmp_attach_nas_stat(grad_nas_t *nas);
void snmp_init_nas_stat();
void snmp_sort_nas_stat();
int snmp_stmt_begin(int finish, void *data, void *up_data);
extern struct cfg_stmt storage_stmt[];
#endif

/* stat.c */
#ifdef USE_SNMP
void stat_init();
void stat_done();
void stat_update(struct radutmp *ut, int status);
void stat_count_ports();
struct nas_stat * find_nas_stat(grad_uint32_t ip_addr);
int stat_get_port_index(grad_nas_t *nas, int port_no);
int stat_get_next_port_no(grad_nas_t *nas, int port_no);
#else
# define stat_init()
# define stat_done()
# define stat_update(ut,status)
#endif

/* snmpserver.c */
int snmp_req_decode(const struct sockaddr_in *srv_sa,
		    const struct sockaddr_in *clt_sa,
		    void *input, size_t inputsize, void **output);
int snmp_req_cmp(void *ap, void *bp);
void snmp_req_free(void *ptr);
void snmp_req_drop(int type, void *data, void *orig_data,
		   int fd, const char *status_str);
int snmp_req_respond(REQUEST *request);
        
/* radutil.c */
radiusd_request_t *radiusd_request_alloc(grad_request_t *req);
void radiusd_request_free(radiusd_request_t *radreq);

char *radius_xlate(struct obstack *obp, char *str,
                   grad_request_t *req, grad_avp_t *reply_pairs);
int radius_eval_avp(radiusd_request_t *req, grad_avp_t *p, grad_avp_t *reply,
		    int allow_xlat);
int radius_eval_avl(radiusd_request_t *req, grad_avp_t *p);
char *util_xlate(struct obstack *sp, char *fmt, grad_request_t *radreq);

/* rewrite.y */
extern struct cfg_stmt rewrite_stmt[];
int parse_rewrite(char *name);

/* radck.c */
int fix_check_pairs(int sf_file, grad_locus_t *loc, char *name, grad_avp_t **pairs);
int fix_reply_pairs(int cf_file, grad_locus_t *loc, char *name, grad_avp_t **pairs);
void radck();

/* checkrad.c */
int checkrad(grad_nas_t *nas, struct radutmp *up);

/* forward.c */
int rad_cfg_forward_auth(int argc, cfg_value_t *argv,
			 void *block_data, void *handler_data);
int rad_cfg_forward_acct(int argc, cfg_value_t *argv,
			 void *block_data, void *handler_data);
void forward_init();
void forward_request(int type, radiusd_request_t *req);

/* dynload.c */
extern struct cfg_stmt dynload_stmt[];
int dynload_stmt_term(int finish, void *block_data, void *handler_data);
void *radiusd_load_ext(const char *name, const char *ident, void **symbol);
void dynload_init();

/* Logging */

/* log output modes */
#define LM_UNKNOWN -1
#define LM_OFF 0
#define LM_FILE 1
#define LM_SYSLOG 2

/* log options */
#define LO_CONS  0x0001
#define LO_PID   0x0002
#define LO_CAT   0x0004
#define LO_PRI   0x0008
#define LO_MSEC  0x0010
#define LO_PERSIST 0x8000

#define RADIUS_DEBUG_BUFFER_SIZE 1024

typedef struct channel Channel;

struct channel {
        char *name;
        int  pmask[GRAD_LOG_NCAT]; 
        int mode;   /* LM_ constant */
        union {
		struct {
			int prio;   /* syslog priority */
			int fac;    /* syslog facility */
			char *tag;  /* syslog tag */
		} sl;
                char *file;      /* file: output file name */
        } id;
        int options;
	char *prefix_hook;       /* prefix hook function */
	char *suffix_hook;       /* suffix hook function */
};

Channel *channel_lookup(char *name);
void channel_free(Channel *chan);
void channel_free_list(Channel *chan);
Channel * log_mark();
void log_release();

void register_channel(Channel *chan);
void register_category(int cat, int pri, grad_list_t *chanlist);

void log_set_to_console(int cat, int pri);
void log_set_default(char *name, int cat, int pri);

void log_open(int cat);
void log_close();

/* sql.c */
#ifdef USE_SQL
void sql_init();
int radiusd_sql_config();
void radiusd_sql_shutdown();
void radiusd_sql_clear_cache();
void radiusd_sql_acct(radiusd_request_t *req);
int radiusd_sql_checkgroup(radiusd_request_t *req, char *groupname);
int radiusd_sql_check_attr_query(radiusd_request_t *req, grad_avp_t **check_pairs);
int radiusd_sql_reply_attr_query(radiusd_request_t *req, grad_avp_t **reply_pairs);
void radiusd_sql_auth_result_query(radiusd_request_t *req, int fail);
void radiusd_sql_cleanup(int type, void *req);

char *radiusd_sql_pass(radiusd_request_t *req, char *data);

# ifdef RADIUS_SERVER_GUILE
SCM sql_exec_query(int type, const char *query);
SCM sql_run_query(int type, const char *query);
# endif

#else
# define sql_init()
# define radiusd_sql_config() 0
# define radiusd_sql_shutdown()
# define radiusd_sql_clear_cache()
# define radiusd_sql_acct(req)
# define radiusd_sql_checkgroup(req, groupname) 1
# define radiusd_sql_check_attr_query(req, check_pairs) 0
# define radiusd_sql_reply_attr_query(req, reply_pairs)
# define radiusd_sql_auth_result_query(req, fail)
# define radiusd_sql_cleanup (void (*)(int, void *)) NULL
#endif
