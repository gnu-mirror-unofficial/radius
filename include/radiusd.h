/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#include <sysdep.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <radius.h>
#include <radpaths.h>
#include <signal.h>
#include <cfg.h>
#include <list.h>

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
#define R_SNMP  2        /* SNMP request */
#define R_MAX   3

#define RS_WAITING   0     /* Request waiting for processing */
#define RS_COMPLETED 1     /* Request is completed */
#define RS_PROXY     2     /* Proxy request waiting for its handler
			      to become free */
#define RS_XMIT      3     /* The request is to be retransmitted to its
			      handler and is waiting for it to
			      become free */

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
	struct sockaddr_in addr;      /* Remote party address */
	REQUEST         *orig;        /* Original request. For proxy */

	void            *update;    
	size_t          update_size;
};

/* Request class structure
 */
typedef struct request_class {
        char *name;           /* Class name */
        int  max_requests;    /* Max.number of pending requests of this type */
        int  ttl;             /* Request time-to-live */
        int  cleanup_delay;   /* Delay before cleaning the completed request */
	int  (*decode)(struct sockaddr_in *sa,
		       void *input, size_t inputsize, void **output);
        int  (*respond)(REQUEST *r);          /* Handler function */
        void (*xmit)(REQUEST *r);             /* Retransmit function */
        int  (*comp)(void *a, void *b);       /* Compare function */
        void (*free)(void *data);             /* Free the associated data */
        void (*drop)(int type, void *data, void *old_data, int fd, char *msg);
	                                      /* Drop the request */
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
        UINT4                   ipaddr;
        char                    longname[MAX_LONGNAME+1];
        u_char                  *secret;
        char                    shortname[MAX_SHORTNAME+1];
} CLIENT;

typedef struct proxy_state {
        UINT4                   ipaddr;
        UINT4                   id;
        UINT4                   proxy_id;
        UINT4                   rem_ipaddr;
} PROXY_STATE;

typedef struct {
	int proxy_id;
	int server_no;
	char realmname[1];
} RADIUS_UPDATE;

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

typedef struct netdef NETDEF;
struct netdef {
        UINT4 ipaddr;        /* IP address */
        UINT4 netmask;
};

typedef struct netname NETNAME;
struct netname {
	char *name;
	LIST /* of NETDEF */ *netlist;
};

typedef struct community Community;
struct community {
        char *name;
        int access;
} ;

typedef struct access_control_list ACL;
struct access_control_list {
        Community *community;   /* community or NULL to deny access */
	LIST /* of NETDEF */ *netlist;
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
        /* struct nas_stat naslist[nas_count];
	   struct port_stat portlist[port_count]; */
} Server_stat;

#define stat_inc(m,a,c) \
 do if (server_stat) {\
        NAS *nas;\
        server_stat -> m . c ++;\
        if ((nas = nas_lookup_ip(a)) != NULL && nas->app_data)\
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
#define MAX_CHILDREN            8

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
extern int radius_mode;
extern int debug_flag;
extern int auth_detail;
extern int acct_detail;
extern int strip_names;
extern int checkrad_assume_logged;
extern size_t max_requests;
extern size_t max_children;
extern char *exec_user;
extern UINT4 expiration_seconds;
extern UINT4 warning_seconds;
extern int use_dbm;
extern UINT4 myip;
extern UINT4 ref_ip;
extern int auth_port;
extern int acct_port;
extern int suspend_flag;
extern int log_mode;
extern int use_guile;
extern char *message_text[MSG_COUNT];
extern char *username_valid_chars;
extern unsigned long stat_start_time;
extern REQUEST_CLASS    request_class[];
extern int max_threads;
extern int num_threads;
#ifdef USE_SERVER_GUILE
extern unsigned scheme_gc_interval;
extern u_int scheme_task_timeout;
#endif
#ifdef USE_SNMP
extern int snmp_port;
extern char *server_id;
extern Server_stat *server_stat;
extern struct cfg_stmt snmp_stmt[];
#endif
extern int auth_comp_flag; 
extern int acct_comp_flag; 

/* Input subsystem (input.c) */

typedef struct input_system INPUT;

INPUT *input_create();
void input_register_method(INPUT *input,
			   const char *name,
			   int (*handler)(int, void *),
			   int (*close)(int, void *),
			   int (*cmp)(const void *, const void *));
int input_register_channel(INPUT *input, char *name, int fd, void *data);
void input_close_channels(INPUT *input);
void input_close_channel_fd(INPUT *input, int fd);
void input_close_channel_data(INPUT *input, char *name, void *data); 
int input_select(INPUT *input, struct timeval *tv);
void *input_find_channel(INPUT *input, char *name, void *data);

/* rpp.c */
int rpp_ready();
int rpp_forward_request(REQUEST *req);
void rpp_remove(pid_t pid);
void rpp_flush();
int rpp_input_handler(int fd, void *data);
int rpp_input_close(int fd, void *data);
int rpp_kill(pid_t pid, int signo);

/* request.c */
REQUEST *request_create(int type, int fd, struct sockaddr_in *sa,
			u_char *buf, size_t bufsize);
void request_free(REQUEST *req);
int request_respond(REQUEST *req);
int request_handle(REQUEST *req, int (*handler)(REQUEST *));
void request_fail(int type, struct sockaddr_in *addr);
void request_init_queue();
void *request_scan_list(int type, list_iterator_t itr, void *closure);
void request_set_status(pid_t pid, int status);
int request_stat_list(QUEUE_STAT stat);
	
/* radiusd.c */
int udp_input_handler(int fd, void *data);
int udp_input_close(int fd, void *data);
int udp_input_cmp(const void *a, const void *b);

int udp_open(int type, UINT4 ipaddr, int port, int nonblock);

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


/* exec.c */
int radius_exec_program(char *, RADIUS_REQ *, VALUE_PAIR **, int, char **);
void filter_cleanup(pid_t pid, int status);
int filter_auth(char *name, RADIUS_REQ *req, VALUE_PAIR **reply_pairs);
int filter_acct(char *name, RADIUS_REQ *req);
int filters_stmt_term(int finish, void *block_data, void *handler_data);
extern struct cfg_stmt filters_stmt[];

/* scheme.c */
void scheme_boot();
void scheme_load(char *filename);
void scheme_load_path(char *pathname);
void scheme_debug(int val);
int scheme_auth(char *procname, RADIUS_REQ *req,
                VALUE_PAIR *user_check, VALUE_PAIR **user_reply_ptr);
int scheme_acct(char *procname, RADIUS_REQ *req);
void scheme_add_load_path(char *path);
void scheme_read_eval_loop();
void scheme_redirect_output();
void start_guile();
int guile_cfg_handler(int argc, cfg_value_t *argv,
		      void *block_data, void *handler_data);
extern struct cfg_stmt guile_stmt[];

/* log.c */
void sqllog __PVAR((int status, char *msg, ...));
int logging_stmt_handler(int argc, cfg_value_t *argv, void *block_data,
			 void *handler_data);
int logging_stmt_end(void *block_data, void *handler_data);
int logging_stmt_begin(int finish, void *block_data, void *handler_data);
extern struct cfg_stmt logging_stmt[];

/* radius.c */

#define REQ_AUTH_OK   0
#define REQ_AUTH_ZERO 1
#define REQ_AUTH_BAD  2

void radius_send_reply(int, RADIUS_REQ *, VALUE_PAIR *, char *, int);
void radius_send_challenge(RADIUS_REQ *radreq, char *msg, char *state, int fd);
int radius_verify_digest(REQUEST *req);

int radius_req_decode(struct sockaddr_in *sa,
		      void *input, size_t inputsize, void **output);
int radius_req_cmp(void *a, void *b);
void radius_req_free(void *req);
void radius_req_drop(int type, void *radreq, void *origreq,
		     int fd, char *status_str);
void radius_req_xmit(REQUEST *request);
int radius_req_failure(int type, struct sockaddr_in *addr);
void radius_req_update(void *req_ptr, void *data_ptr);
int radius_respond(REQUEST *req);

/* shmem.c */
int shmem_alloc(size_t size);
void shmem_free();
void *shmem_get(size_t size, int zero);

/* pam.c */
int pam_pass(char *name, char *passwd, const char *pamauth, char **reply_msg);
#define PAM_DEFAULT_TYPE    "radius"

/* proxy.c */
int rad_proxy(REQUEST *req);
void rad_proxy_free(RADIUS_REQ *req);
int proxy_send(REQUEST *req);
int proxy_receive(RADIUS_REQ *radreq, RADIUS_REQ *oldreq, int activefd);
void proxy_retry(int type, void *radreq, void *orig_req,
		 int fd, char *status_str);

/*FIXME*/
/* acct.c */
int rad_accounting(RADIUS_REQ *, int, int);
int radzap(UINT4 nas, int port, char *user, time_t t);
int rad_check_multi(char *name, VALUE_PAIR *request, int maxsimul, int *pcount);
int rad_check_realm(REALM *realm);
int write_detail(RADIUS_REQ *radreq, int authtype, char *f);


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

/* auth.c */
int rad_auth_init(RADIUS_REQ *radreq, int activefd);
int rad_authenticate (RADIUS_REQ *, int);
void req_decrypt_password(char *password, RADIUS_REQ *req, VALUE_PAIR *pair);

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
struct nas_stat * find_nas_stat(UINT4 ip_addr);
int stat_get_port_index(NAS *nas, int port_no);
int stat_get_next_port_no(NAS *nas, int port_no);
#else
# define stat_init()
# define stat_done()
# define stat_update(ut,status)
#endif

/* snmpserver.c */
int snmp_req_decode(struct sockaddr_in *sa,
		    void *input, size_t inputsize, void **output);
int snmp_req_cmp(void *ap, void *bp);
void snmp_req_free(void *ptr);
void snmp_req_drop(int type, void *data, void *orig_data,
		   int fd, char *status_str);
int snmp_req_respond(REQUEST *request);
        
/* radutil.c */
char *radius_xlate(struct obstack *obp, char *str,
                   RADIUS_REQ *req, VALUE_PAIR *reply_pairs);

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



/* checkrad.c */
int checkrad(NAS *nas, struct radutmp *up);



