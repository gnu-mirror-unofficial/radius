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
/*
 *	@(#) $Id$
 */

#include <stdio.h>
#include <sysdep.h>
#include <radius.h>
#include <radpaths.h>
#include <mem.h>
#include <log.h>

#define NITEMS(a) sizeof(a)/sizeof((a)[0])

/* Server data structures */
struct radutmp; /* declared in radutmp.h */
struct obstack;

typedef struct {
	unsigned delayed_hup_wait;
	int checkrad_assume_logged;
	int max_requests;
	char *exec_user;
	char *exec_group;
} Config;

typedef struct {
	UINT4 ipaddr;
	int   port;
	int   timeout;
	int   retry;
} Notify;

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
	int  spawn;           /* execute handler as a separate process */
	int  (*handler)();    /* Handler function */
	void (*xmit)();       /* Retransmit function */
	int  (*comp)();       /* Compare function */
	void (*free)();       /* Free */
	void (*drop)();       /* Drop request error message */
	int  (*setup)();      /* Setup function */
	void (*cleanup)();    /* Cleanup function */
} REQUEST_CLASS;


/* ************************** Data structures ****************************** */

#define MAX_DICTNAME  32
#define MAX_SECRETLEN 32
#define MAX_REALMNAME 256
#define MAX_LONGNAME  256
#define MAX_SHORTNAME 32

#define AF_CHECKLIST   0x0001  /* The attribute is valid in checklist */
#define AF_REPLYLIST   0x0002  /* The attribute is valid in replylist */
#define AF_ADD_REPLACE 0
#define AF_ADD_APPEND  1
#define AF_ADD_NONE    2

#define AF_DEFAULT_FLAGS (AF_CHECKLIST|AF_REPLYLIST)
#define AF_DEFAULT_ADD   AF_ADD_APPEND

/* Dictionary attribute */
typedef struct dict_attr {
	struct dict_attr	*next;
	char			name[MAX_DICTNAME+1];
	int			value;
	int			type;
	int			vendor;
	int                     flags;
	int                     additivity; 
} DICT_ATTR;

/* Dictionary value */
typedef struct dict_value {
	struct dict_value	*next;
	char			attrname[MAX_DICTNAME+1];
	char			name[MAX_DICTNAME+1];
	int			value;
} DICT_VALUE;

/* Dictionary vendor information */
typedef struct dict_vendor {
	struct dict_vendor	*next;
	char			vendorname[MAX_DICTNAME+1];
	int			vendorpec;
	int			vendorcode;
} DICT_VENDOR;

/* An attribute/value pair */
typedef struct value_pair {
	struct value_pair	*next;      /* Link to next A/V pair in list */
	char	                *name;      /* Attribute name */
	int			attribute;  /* Attribute value */
	int			type;       /* Data type */
	int                     eval;       /* Evaluation flag */
	int                     additivity; 
	int			operator;   /* Comparison operator */
	union {
		UINT4		ival;       /* integer value */
		struct {
			int	s_length;   /* length of s_value w/o
					     * trailing 0
					     */
			char	*s_value;   /* string value */
		} string;
	} v;
	
#define lvalue v.ival
#define strvalue v.string.s_value
#define strlength v.string.s_length

} VALUE_PAIR;

typedef struct radius_req {
	UINT4			ipaddr;
	u_short			udp_port;
	u_char			id;
	u_char			code;
	u_char			vector[AUTH_VECTOR_LEN];
	u_char			secret[AUTH_PASS_LEN];
	u_char		        digest[AUTH_PASS_LEN];
	VALUE_PAIR		*request;
	u_char			*data;		/* Raw received data */
	int			data_len;       /* Length of raw data */
	int                     data_alloced;   /* Was the data malloced */
        /* Proxy support fields */
	char			*realm;         /* stringobj, actually */
	int			validated;	/* Already md5 checked */
	UINT4			server_ipaddr;
	UINT4			server_id;
	VALUE_PAIR		*server_reply;	/* Reply from other server */
	int			server_code;	/* Reply code from other srv */
} RADIUS_REQ;

typedef struct client {
	struct client		*next;
	UINT4			ipaddr;
	char			longname[MAX_LONGNAME+1];
	u_char			secret[AUTH_PASS_LEN];
	char			shortname[MAX_SHORTNAME+1];
} CLIENT;

typedef struct proxy_id {
	struct proxy_id         *next;
	UINT4                   ipaddr;
	u_char                  id;
} PROXY_ID;

typedef struct proxy_state {
	UINT4			ipaddr;
	UINT4			id;
	UINT4			proxy_id;
	UINT4			rem_ipaddr;
} PROXY_STATE;

#ifdef USE_SNMP
struct nas_stat;
#endif
struct radck_arg;

typedef struct nas {
	struct nas		*next;
	UINT4			ipaddr;
	char			longname[MAX_LONGNAME+1];
	char			shortname[MAX_SHORTNAME+1];
	char			nastype[MAX_DICTNAME+1];
	struct radck_arg        *args;
#ifdef USE_SNMP
	struct nas_stat         *nas_stat;
#endif	
} NAS;

typedef struct realm {
	struct realm		*next;
	char			realm[MAX_REALMNAME+1];
	char			server[MAX_LONGNAME+1];
	UINT4			ipaddr;
	int			auth_port;
	int			acct_port;
	int			striprealm;
	int                     maxlogins;
} REALM;

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

struct keyword {
	char *name;
	int tok;
};

#ifdef USE_SNMP


#define SNMP_RO 1
#define SNMP_RW 2

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

typedef unsigned long counter;

struct radstat {
	struct timeval start_time;
	counter port_active_count;
	counter port_idle_count;
};

typedef enum {
	serv_other=1,
	serv_reset,
	serv_init,
	serv_running
} serv_stat;

typedef enum {
	port_idle = 1,
	port_active
} port_status;

typedef struct {
	serv_stat status;
	struct timeval reset_time;
	counter num_req;
	counter num_invalid_req;
	counter num_dup_req;
	counter num_resp;
	counter num_bad_req;
	counter num_bad_sign;
	counter num_dropped;
	counter num_norecords;
	counter num_unknowntypes;
} Acct_server_stat;

typedef struct {
	serv_stat status;
	struct timeval reset_time;
	counter num_access_req;
	counter num_invalid_req;
	counter num_dup_req;
	counter num_accepts;
	counter num_rejects;
	counter num_challenges;
	counter num_bad_req;
	counter num_bad_auth;
	counter num_dropped;
	counter num_unknowntypes;
} Auth_server_stat;

typedef struct {
	struct timeval start_time;
	int nas_count; /* Number of NASes in the nas_stat tail */
	int nas_index; /* Next available NAS index */
	Auth_server_stat auth;
	Acct_server_stat acct;
	/* a tail of nas_stat structures follows */
} Server_stat;

struct nas_stat {
	int index;
	UINT4 ipaddr;
	counter ports_active;
	counter ports_idle;
	Auth_server_stat auth;
	Acct_server_stat acct;
};


#define stat_inc(m,a,c) \
 do {\
	NAS *nas;\
	server_stat->##m . ##c ++;\
	if ((nas = nas_lookup_ip(a)) != NULL && nas->nas_stat)\
		nas->nas_stat-> ##m . ##c ++;\
 } while (0)

extern struct radstat radstat;

#else
#define stat_inc(m,a,c)
#endif


enum {
	PW_OPERATOR_EQUAL = 0,	        /* = */
	PW_OPERATOR_NOT_EQUAL,	        /* != */
	PW_OPERATOR_LESS_THAN,	        /* < */
	PW_OPERATOR_GREATER_THAN,	/* > */
	PW_OPERATOR_LESS_EQUAL,	        /* <= */
	PW_OPERATOR_GREATER_EQUAL,	/* >= */
	PW_NUM_OPERATORS		/* number of operators */
};

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	60
#define CLEANUP_DELAY		10
#define MAX_REQUESTS		255

#define VENDOR(x) (x >> 16)

/*
 * Authentication results
 */
#define AUTH_OK      0 /* OK */
#define AUTH_FAIL    1 /* Password fail */
#define AUTH_NOUSER  2 /* No such user  */
#define AUTH_REJECT  3 /* Rejected */


/*
 *	Global variables.
 */
extern char		*progname;
extern Config           config;
extern Notify           notify_cfg;
extern int		debug_flag;
extern int              verbose;
extern int              auth_detail;
extern int              strip_names;
extern char     	*radius_dir;
extern char	        *radlog_dir;
extern char      	*radacct_dir;
extern char             *radutmp_path;
extern char             *radwtmp_path;
extern char             *radstat_path;
extern char             *bug_report_address;
extern UINT4		expiration_seconds;
extern UINT4		warning_seconds;
extern int		radius_pid;
extern int		use_dbm;
extern UINT4		myip;
extern UINT4		warning_seconds;
extern int		auth_port;
extern int		acct_port;
extern int              cntl_port;
extern int              suspend_flag;

extern unsigned long stat_start_time;
extern REQUEST_CLASS    request_class[];

#ifdef USE_SNMP
extern int              snmp_port;
extern char *server_id;
extern Server_stat *server_stat;
#endif

extern UINT4            notify_ipaddr;
extern int              notify_port;

/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(RADIUS_REQ *, int);
int		radzap(UINT4 nas, int port, char *user, time_t t);
int		rad_check_multi(char *name, VALUE_PAIR *request, int maxsimul);
int             write_detail(RADIUS_REQ *radreq, int authtype, char *f);
void            rad_acct_xmit(int type, int code, void *data, int fd);

/* dict.c */
int		dict_init();
DICT_ATTR	*attr_number_to_dict(int);
DICT_ATTR       *attr_name_to_dict(char *);
DICT_VALUE      *value_name_to_value(char *);
DICT_VALUE      *value_lookup(UINT4, char *);
int             vendor_id_to_pec(int);
int             vendor_pec_to_id(int);
char            *vendor_pec_to_name(int);
int             vendor_name_to_id(char *);


/* md5.c */

void		md5_calc(u_char *, u_char *, u_int);

/* radiusd.c */
void		debug_pair(char *, VALUE_PAIR *);
void		sig_cleanup(int);
int             server_type();
int             stat_request_list(int (*report)());
void *          scan_request_list(int type, int (*handler)(), void *closure);
int             set_nonblocking(int fd);
int             master_process();
int             rad_flush_queues();
void            schedule_restart();

/* avl.c */
VALUE_PAIR *avp_alloc();
void avp_free();
void		avl_free(VALUE_PAIR *);
VALUE_PAIR	*avl_find(VALUE_PAIR *, int);
void		avl_delete(VALUE_PAIR **, int);
void		avl_add_list(VALUE_PAIR **, VALUE_PAIR *);
void		avl_add_pair(VALUE_PAIR **, VALUE_PAIR *);
VALUE_PAIR     *avl_dup(VALUE_PAIR *from);
VALUE_PAIR     *avp_dup(VALUE_PAIR *vp);
void            avl_merge(VALUE_PAIR **dst_ptr, VALUE_PAIR **src_ptr);
VALUE_PAIR     *avp_create(int attr, int length, char *strval, int lval);
void		avl_move_attr(VALUE_PAIR **to, VALUE_PAIR **from, int attr);

/* util.c */
char *		ip_hostname (UINT4);
UINT4		get_ipaddr (char *);
int		good_ipaddr(char *);
char *		ipaddr2str(char *, UINT4);
UINT4		ipstr2long(char *);
struct passwd	*rad_getpwnam(char *);
void		radreq_free(RADIUS_REQ *radreq);
void            rad_lock(int fd, size_t size, off_t off, int whence);
void            rad_unlock(int fd, size_t size, off_t off, int whence);
char           *mkfilename(char *, char*);
char           *mkfilename3(char *dir, char *subdir, char *name);
int             backslash(int c);
void string_copy(char *d, char *s, int  len);
#define STRING_COPY(s,d) string_copy(s,d,sizeof(s)-1)

/* radius.c */
int		rad_send_reply(int, RADIUS_REQ *, VALUE_PAIR *, char *, int);
RADIUS_REQ	*radrecv (UINT4, u_short, u_char *, int);
int		calc_digest (u_char *, RADIUS_REQ *);
int		calc_acctdigest(u_char *digest, RADIUS_REQ *radreq);
void            send_challenge(RADIUS_REQ *radreq, char *msg, char *state, int activefd);

/* nas.c */
NAS *nas_next(NAS *p);
int nas_read_file(char *file);
NAS *nas_lookup_name(char *name);
NAS *nas_lookup_ip(UINT4 ipaddr);
#ifdef USE_SNMP
NAS *nas_lookup_index(int ind);
#endif
char *nas_ip_to_name(UINT4 ipaddr);
char *nas_request_to_name(RADIUS_REQ *radreq);


/* files.c */
int		user_find(char *name, RADIUS_REQ *,
			  VALUE_PAIR **, VALUE_PAIR **);
int		userparse(char *buf, VALUE_PAIR **first_pair, char **errmsg);
void		presuf_setup(VALUE_PAIR *request_pairs);
int		hints_setup(RADIUS_REQ *request);
int		huntgroup_access(RADIUS_REQ *radreq);
CLIENT		*client_lookup_ip(UINT4 ipno);
char		*client_lookup_name(UINT4 ipno);
int		read_clients_file(char *);
REALM		*realm_find(char *);
NAS		*nas_find(UINT4 ipno);
NAS             *nas_by_name(char *name);
char		*nas_name(UINT4 ipno);
char		*nas_name2(RADIUS_REQ *r);
int		read_naslist_file(char *);
int		reload_config_file(enum reload_what);
int		presufcmp(VALUE_PAIR *check, char *name, char *rest);
int             get_config();
int             get_deny(char *user);
NAS *           findnasbyindex(int);
char *          make_server_ident();
void            dump_users_db();
void            strip_username(int do_strip, char *name,
			       VALUE_PAIR *check_item, char *stripped_name);

/* version.c */
void		version();


/* pam.c */
#ifdef USE_PAM
int		pam_pass(char *name, char *passwd, const char *pamauth,
			 char **reply_msg);
# define PAM_DEFAULT_TYPE    "radius"
#endif

/* proxy.c */
int rad_proxy(RADIUS_REQ *radreq, int activefd);
void rad_proxy_free(RADIUS_REQ *req);
int proxy_send(RADIUS_REQ *radreq, int activefd);
int proxy_receive(RADIUS_REQ *radreq, int activefd);
void proxy_cleanup();

/* auth.c */
int		rad_auth_init(RADIUS_REQ *radreq, int activefd);
int		rad_authenticate (RADIUS_REQ *, int);
int  rad_check_password(RADIUS_REQ *radreq, int activefd,
			VALUE_PAIR *check_item,
			VALUE_PAIR *namepair,
			u_char *pw_digest, char **user_msg, char *userpass);

/* exec.c */
int radius_exec_program(char *, RADIUS_REQ *, VALUE_PAIR **,
			int, char **user_msg);

/* menu.c */
void process_menu(RADIUS_REQ *radreq, int fd, u_char *pw_digest);
char * get_menu(char *menu_name);

/* fixalloc.c */
#define Alloc_entry(t) alloc_entry(sizeof(t))
RADIUS_REQ *radreq_alloc();
#define free_request free_entry

#define MAX_PATH_LENGTH                 256
#define MAX_MENU_SIZE                   4096
#define MAX_MENU_NAME                   128
#define MAX_MENU_INPUT                  32
#define MAX_STATE_VALUE                 128
#define RAD_BUFFER_SIZE                 4096


/* timestr.c */
int		timestr_match(char *, time_t);

/* notify.c */
int notify(char *login, int what, long *ttl_ptr);
int notify_acct(char *login, int what);
int timetolive(char *user_name, long *ttl);

/* shmem.c */
int shmem_alloc(unsigned size);
void shmem_free();
void shmem_free();
void * shmem_get(unsigned size, int zero);

#ifdef USE_SNMP
/* snmpserv.c */
void snmp_tree_init();
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
#endif

/* raddb.c */
int read_raddb_file(char *name, int vital, int fcnt, int (*fun)(),
		    void *closure);

int xlat_keyword(struct keyword *kw, char *str, int def);

/* mem.c */
void *emalloc(size_t);
void efree(void*);
char *estrdup(char *);

/* radpaths.c */
void radpath_init();

/* stat.c */
void stat_init();
void stat_done();
void stat_update(struct radutmp *ut, int status);
void stat_create();
void stat_count_ports();

/* users.y */
int parse_file(char *file, void *c, int (*f)());
int user_gettime(char *valstr, struct tm *tm);
VALUE_PAIR *install_pair(char *name, int op, char *valstr);

/* snmpserver.c */
struct sockaddr_in;
struct snmp_req * rad_snmp_respond(u_char *buf, int len,
				   struct sockaddr_in *sa);
int snmp_req_cmp(struct snmp_req *a, struct snmp_req *b);
void snmp_req_free(struct snmp_req  *req);
void snmp_req_drop(int type, struct snmp_req *req, char *status_str);
int snmp_answer(struct snmp_req *req, int fd);
	
/* radutil.c */
char *radius_xlate(struct obstack *obp, char *str,
		   RADIUS_REQ *req, VALUE_PAIR *reply_pairs);

/* intl.c */
void app_setup();

/* log.c */
void sqllog(/* int status, char *msg, va_alist */);
char * debug_print_pair(VALUE_PAIR *pair);

/* rewrite.y */
int run_rewrite(char *name, VALUE_PAIR *req);
int parse_rewrite();

/* md5crypt.c */
char * md5crypt(const char *pw, const char *salt);

