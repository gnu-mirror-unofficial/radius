/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
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

#ifndef _gnu_radius_radius_h
#define _gnu_radius_radius_h

#include <radius/types.h>
#include <radius/list.h>
#include <radius/envar.h>
#include <radius/mem.h>
#include <radius/dictionary.h>
#include <stdarg.h>

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
# ifdef TIME_WITH_SYS_TIME
#  include <time.h>
# endif
#else
# include <time.h>
#endif

struct obstack;


#define DOTTED_QUAD_LEN         16

#define AUTH_VECTOR_LEN         16
#define AUTH_PASS_LEN           16
#define AUTH_DIGEST_LEN         16
#define AUTH_STRING_LEN        253

typedef struct {
        u_char code;            /* Request code (see RT_ macros below)*/ 
        u_char id;              /* Request ID */
        u_short length;         /* Request length */ 
        u_char vector[AUTH_VECTOR_LEN]; /* Request authenticator */
} grad_packet_header_t;

#define CHAP_VALUE_LENGTH               16

/* Radius data types */
#define TYPE_INVALID                   -1
#define TYPE_STRING                     0
#define TYPE_INTEGER                    1
#define TYPE_IPADDR                     2
#define TYPE_DATE                       3

/* Request types */
#define RT_ACCESS_REQUEST               1
#define RT_ACCESS_ACCEPT                2
#define RT_ACCESS_REJECT                3
#define RT_ACCOUNTING_REQUEST           4
#define RT_ACCOUNTING_RESPONSE          5
#define RT_ACCOUNTING_STATUS            6
#define RT_PASSWORD_REQUEST             7
#define RT_PASSWORD_ACK                 8
#define RT_PASSWORD_REJECT              9
#define RT_ACCOUNTING_MESSAGE           10
#define RT_ACCESS_CHALLENGE             11
#define RT_STATUS_SERVER                12
#define RT_STATUS_CLIENT                13

/* These are not implemented yet */
#define RT_ASCEND_TERMINATE_SESSION     31
#define RT_ASCEND_EVENT_REQUEST         33
#define RT_ASCEND_EVENT_RESPONSE        34
#define RT_ASCEND_ALLOCATE_IP           51
#define RT_ASCEND_RELEASE_IP            52

/* Basic structures */

enum grad_operator {
        grad_operator_equal = 0,             /* = */
        grad_operator_not_equal,             /* != */
        grad_operator_less_than,             /* < */
        grad_operator_greater_than,          /* > */
        grad_operator_less_equal,            /* <= */
        grad_operator_greater_equal,         /* >= */
        NUM_OPERATORS                   /* number of operators */
};

/* ************************** Data structures ****************************** */

#define MAX_DICTNAME  32
#define MAX_SECRETLEN 32
#define MAX_REALMNAME 256
#define MAX_LONGNAME  256
#define MAX_SHORTNAME 32

/* Attribute flags and properties:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | A | E |   P   | LHS | RHS |     USER FLAGS    |               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   A - Additivity bits
   E - Encryption bits
   P - Property flags
   LHS - Syntax flags for LHS
   RHS - Syntax flags for RHS
   
   Bits 7 and 24-31 are unused */

/* Attribute properties */
#define AP_ADD_REPLACE   0
#define AP_ADD_APPEND    1
#define AP_ADD_NONE      2

/* Encryption bits */
#define AP_ENCRYPT_RFC2138 0x4 /* Encrypted per RFC 2138 */
#define AP_ENCRYPT_RFC2868 0x8 /* Encrypted per RFC 2868 */

#define AP_ENCRYPT (AP_ENCRYPT_RFC2138|AP_ENCRYPT_RFC2868)

#define AP_PROPAGATE     0x10 /* Propagate attribute through the proxy chain */
#define AP_INTERNAL      0x20 /* Internal attribute. */
#define AP_BINARY_STRING 0x40 /* Binary string value. No str..() functions
				 should be used */
#define AP_TRANSLATE     0x80 /* Attribute has dictionary translations */
				 
#define AP_USER_FLAG(n) (0x4000<<(n))

#define ADDITIVITY(val) ((val) & 0x3)
#define SET_ADDITIVITY(val,a) ((val) = ((val) & ~0x3) | (a))

/* Configuration files types */
#define CF_USERS      0
#define CF_HINTS      1
#define CF_HUNTGROUPS 2
#define CF_MAX        3

#define AF_LHS(cf) (0x0100<<(cf))
#define AF_RHS(cf) (0x0800<<(cf))

#define AF_DEFAULT_FLAGS (AF_LHS(0)|AF_LHS(1)|AF_LHS(2)\
                         |AF_RHS(0)|AF_RHS(1)|AF_RHS(2))
#define AP_DEFAULT_ADD   AP_ADD_APPEND


#define PORT_AUTH 0
#define PORT_ACCT 1
#define PORT_MAX  2

typedef struct {                
	char *file;             /* File name */
	size_t line;            /* Line number */
} grad_locus_t;

typedef struct {
	grad_uint32_t addr;     /* Server IP address */
	u_char id;              /* Current id */
} grad_server_id_t;

typedef struct netdef grad_netdef_t;
struct netdef {
        grad_uint32_t ipaddr;        /* IP address */
        grad_uint32_t netmask;       /* Network mask */
};

typedef struct radius_server grad_server_t;
struct radius_server {
        char   *name;           /* Symbolic name of this server */
        grad_uint32_t addr;     /* IP address of it */
        int    port[PORT_MAX];  /* Ports to use */
        char   *secret;         /* Shared secret */
	off_t  id_offset;       /* Offset of the grad_server_id_t in the id file */
};

typedef struct {
        grad_uint32_t source_ip; /* Source IP address for xmits */
        unsigned timeout;        /* Amount of time to wait for the response */
        unsigned retries;        /* Number of re-sends to each server before
				    giving up */
	size_t buffer_size;      /* Size of the recv buffer */
        grad_list_t   *servers;  /* List of servers */
} grad_server_queue_t;    

struct value_pair;
typedef int (*attr_parser_fp)(struct value_pair *p, char **s);

/* Dictionary attribute */

typedef struct dict_attr grad_dict_attr_t;
struct dict_attr {
        char   *name;          /* Attribute name */
	int    value;          /* Attribute value */
	int    type;           /* Data type */
	int    vendor;         /* Vendor index */
	int    prop;           /* Properties */
	attr_parser_fp parser; /* Not-NULL for "abinary" */
};

/* Dictionary value */
typedef struct dict_value {
        char *name;             /* Symbolic name */
        grad_dict_attr_t *attr; /* Attribute for which this value is defined */
        int value;              /* Numeric value */
} grad_dict_value_t;

/* Dictionary vendor information */
typedef struct dict_vendor {
        char *vendorname;       /* Symbolic name */
        int  vendorpec;         /* PEC */
        int  vendorcode;        /* Internal code of this vendor */
} grad_dict_vendor_t;

enum grad_avp_eval_type {
	eval_const,
	eval_interpret,
	eval_compiled
};

/* An attribute/value pair */
typedef struct value_pair {
        struct value_pair       *next;      /* Link to next A/V pair in list */
        char                    *name;      /* Attribute name */
        int                     attribute;  /* Attribute value */
        int                     type;       /* Data type */
        enum grad_avp_eval_type eval_type;  /* Evaluation flag */
        int                     prop;       /* Properties */ 
        enum grad_operator operator;   /* Comparison operator */
        union {
                grad_uint32_t           ival;       /* integer value */
                struct {
                        int     s_length;   /* length of s_value w/o
                                             * trailing 0
                                             */
                        char    *s_value;   /* string value */
                } string;
        } v;
        
#define avp_lvalue v.ival
#define avp_strvalue v.string.s_value
#define avp_strlength v.string.s_length

} grad_avp_t;

typedef struct nas {
	grad_netdef_t netdef;
        char longname[MAX_LONGNAME+1];
        char shortname[MAX_SHORTNAME+1];
        char nastype[MAX_DICTNAME+1];
        grad_envar_t *args;
        void *app_data;
} grad_nas_t;

typedef struct realm {
        char realm[MAX_REALMNAME+1];
	grad_envar_t *args;
	grad_server_queue_t *queue;
} grad_realm_t;

typedef struct radius_req {
        grad_uint32_t ipaddr;       /* Source IP address */
        u_short       udp_port;     /* Source port */
        u_char        id;           /* Request identifier */
        u_char        code;         /* Request code */
        u_char        vector[AUTH_VECTOR_LEN]; /* Rq authenticator */
        u_char        *secret;      /* Shared secret */
        grad_avp_t    *request;     /* Request pairs */

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
	char          *remote_user;  /* Remote username (stringobj)*/
        u_char        remote_auth[AUTH_VECTOR_LEN];
	
        int           server_code;   /* Reply code from other srv */
        grad_avp_t    *server_reply; /* Reply from other server */
} grad_request_t;

struct keyword {
        char *name;
        int tok;
};


typedef struct matching_rule grad_matching_rule_t;
struct matching_rule {
        char *name;
        grad_avp_t *lhs;
        grad_avp_t *rhs;
	grad_locus_t loc;
};

/* External variables */

extern char *radius_dir;
extern char *radlog_dir;
extern char *radacct_dir;
extern char *radutmp_path;
extern char *radwtmp_path;
extern char *radstat_path;
extern char *radmsgid_path;
extern char *radpid_dir;
extern char *bug_report_address;

/* Parser */
extern grad_locus_t grad_parser_source_locus;

int grad_parser_lex_init(char *name);
void grad_parser_lex_finish();
int grad_parser_lex_sync();

#define NITEMS(a) sizeof(a)/sizeof((a)[0])

size_t grad_create_pdu(void **rptr, int code, int id,
		       u_char *vector, u_char *secret,
		       grad_avp_t *pairlist, char *msg);

grad_request_t *grad_decode_pdu(grad_uint32_t host,
				u_short udp_port, u_char *buffer,
				size_t length);

int grad_server_send_reply(int fd, grad_request_t *radreq);
int grad_server_send_challenge(int fd, grad_request_t *radreq,
			       char *msg, char *state);


/* dict.c */
#define GRAD_VENDOR_CODE(x) (x >> 16)
#define GRAD_VSA_ATTR_NUMBER(attrno,code) ((attrno) | (code) << 16)

int grad_dict_init();
grad_dict_attr_t *grad_attr_number_to_dict(int);
grad_dict_attr_t *grad_attr_name_to_dict(char *);
grad_dict_value_t *grad_value_name_to_value(char *, int);
grad_dict_value_t *grad_value_lookup(grad_uint32_t, char *);
int grad_vendor_id_to_pec(int);
int grad_vendor_pec_to_id(int);
char *grad_vendor_pec_to_name(int);
int grad_vendor_name_to_id(char *);

typedef int (*dict_iterator_fp)(void *data,
				char const *, grad_dict_attr_t const *);
void grad_dictionary_iterate(dict_iterator_fp fp, void *closure);

typedef int (*dict_value_iterator_fp)(void *, grad_dict_value_t*);
void grad_dictionary_value_iterate(dict_value_iterator_fp fp, void *closure);

/* md5crypt.c */
char *grad_md5crypt(const char *pw, const char *salt, char *pwbuf,
		    size_t pwlen);

/* avl.c */
grad_avp_t *grad_avp_alloc();
void grad_avp_free();
void grad_avl_free(grad_avp_t *);
grad_avp_t *grad_avl_find(grad_avp_t *, int);
grad_avp_t *grad_avl_find_n(grad_avp_t *, int, int);
void grad_avl_delete(grad_avp_t **, int);
void grad_avl_delete_n(grad_avp_t **first, int attr, int n);
void grad_avl_add_list(grad_avp_t **, grad_avp_t *);
void grad_avl_add_pair(grad_avp_t **, grad_avp_t *);
grad_avp_t *grad_avl_dup(grad_avp_t *from);
grad_avp_t *grad_avp_dup(grad_avp_t *vp);
void grad_avl_merge(grad_avp_t **dst_ptr, grad_avp_t **src_ptr);
grad_avp_t *grad_avp_create(int attr);
grad_avp_t *grad_avp_create_integer(int attr, grad_uint32_t value);
grad_avp_t *grad_avp_create_string(int attr, char *value);
grad_avp_t *grad_avp_create_binary(int attr, int length, u_char *value);
void grad_avl_move_attr(grad_avp_t **to, grad_avp_t **from, int attr);
void grad_avl_move_pairs(grad_avp_t **to, grad_avp_t **from,
			 int (*fun)(void *, grad_avp_t *), void *closure);
int grad_avp_cmp(grad_avp_t *a, grad_avp_t *b);
int grad_avl_cmp(grad_avp_t *a, grad_avp_t *b, int prop);
int grad_avp_null_string_p(grad_avp_t *pair);
	
extern int resolve_hostnames;

char *grad_ip_gethostname (grad_uint32_t, char *buf, size_t size);
grad_uint32_t grad_ip_gethostaddr (const char *);
char *grad_ip_iptostr(grad_uint32_t, char *);
grad_uint32_t grad_ip_strtoip(const char *);
int grad_ip_getnetaddr(const char *str, grad_netdef_t *netdef);
int grad_ip_in_net_p(const grad_netdef_t *netdef, grad_uint32_t ipaddr);

/* nas.c */
grad_iterator_t *grad_nas_iterator();
int grad_nas_read_file(char *file);
grad_nas_t *grad_nas_lookup_name(char *name);
grad_nas_t *grad_nas_lookup_ip(grad_uint32_t ipaddr);
char *grad_nas_ip_to_name(grad_uint32_t ipaddr, char *buf, size_t size);
grad_nas_t *grad_nas_request_to_nas(const grad_request_t *radreq);
char *grad_nas_request_to_name(const grad_request_t *radreq, char *buf, size_t size);

/* realms.c */
grad_realm_t *grad_realm_lookup_name(char *name);
grad_realm_t *grad_realm_lookup_ip(grad_uint32_t ip);
int grad_read_realms(char *filename, int auth_port, int acct_port,
		     int (*set_secret)());
int grad_realm_verify_ip(grad_realm_t *realm, grad_uint32_t ip);
int grad_realm_strip_p(grad_realm_t *r);
size_t grad_realm_get_quota(grad_realm_t *r);
grad_request_t *grad_request_alloc();

/* raddb.c */
int grad_read_raddb_file(char *name, int vital,
			 char *delim,
			 int (*fun)(void*,int,char**,grad_locus_t*),
			 void *closure);

/* radpaths.c */
void grad_path_init();

/* users.y */
typedef int (*register_rule_fp) (void *, grad_locus_t *, char *,
				 grad_avp_t *, grad_avp_t *);
int grad_parse_rule_file(char *file, void *c, register_rule_fp f);
int grad_parse_time_string(char *valstr, struct tm *tm);
grad_avp_t *grad_create_pair(grad_locus_t *loc, char *name,
			     enum grad_operator op, char *valstr);


/* util.c */
void grad_request_free(grad_request_t *radreq);
void grad_lock_file(int fd, size_t size, off_t off, int whence);
void grad_unlock_file(int fd, size_t size, off_t off, int whence);
char *grad_mkfilename(char *, char*);
char *grad_mkfilename3(char *dir, char *subdir, char *name);
int grad_decode_backslash(int c);
void grad_string_copy(char *d, char *s, int  len);
#define GRAD_STRING_COPY(s,d) grad_string_copy(s,d,sizeof(s)-1)
char *grad_format_pair(grad_avp_t *pair, int typeflag, char **save);
int grad_format_string_visual(char *buf, int runlen, char *str, int len);
char *grad_op_to_str(enum grad_operator op);
enum grad_operator grad_str_to_op(char *str);
int grad_xlat_keyword(struct keyword *kw, const char *str, int def);
void grad_obstack_grow_backslash_num(struct obstack *stk, char *text,
				     int len, int base);
void grad_obstack_grow_backslash(struct obstack *stk, char *text,
				 char **endp);


/* cryptpass.c */
void grad_encrypt_password(grad_avp_t *pair, char *password,
			   char *vector, char *secret);
void grad_decrypt_password(char *password, grad_avp_t *pair,
			   char *vector, char *secret);
void grad_decrypt_password_broken(char *password, grad_avp_t *pair,
				  char *vector, char *secret);
void grad_encrypt_tunnel_password(grad_avp_t *pair, u_char tag, char *password,
				  char *vector, char *secret);
void grad_decrypt_tunnel_password(char *password, u_char *tag,
				  grad_avp_t *pair,
				  char *vector, char *secret);

/* gethost_r.c */
struct hostent *grad_gethostbyname_r(const char *name, struct hostent *result,
				     char *buffer, int buflen, int *h_errnop);
struct hostent *grad_gethostbyaddr_r(const char *addr, int length,
				     int type, struct hostent *result,
				     char *buffer, int buflen, int *h_errnop);

struct passwd *grad_getpwnam_r(const char *name, struct passwd *result,
			       char *buffer, int buflen);
struct group *grad_getgrnam(const char *name);

/* client.c */
#define RADCLT_ID            0x1
#define RADCLT_AUTHENTICATOR 0x2

grad_request_t *grad_client_send0(grad_server_queue_t *config,
				  int port_type, int code,
				  grad_avp_t *pairlist, int flags, int *authid,
				  u_char *authvec);
grad_request_t *grad_client_send(grad_server_queue_t *config,
				 int port_type, int code,
				 grad_avp_t *pairlist);
unsigned grad_client_message_id(grad_server_t *server);
grad_server_queue_t *grad_client_create_queue(int read_cfg,
					      grad_uint32_t source_ip,
					      size_t bufsize);
void grad_client_destroy_queue(grad_server_queue_t *queue);
grad_server_t *grad_client_alloc_server(grad_server_t *src);
grad_server_t *grad_client_dup_server(grad_server_t *src);

void grad_client_free_server(grad_server_t *server);
void grad_client_append_server(grad_server_queue_t *qp, grad_server_t *server);
void grad_client_clear_server_list(grad_server_queue_t *qp);
grad_server_t *grad_client_find_server(grad_server_queue_t *qp, char *name);
void grad_client_random_vector(char *vector);
grad_avp_t *grad_client_encrypt_pairlist(grad_avp_t *plist,
					 u_char *vector, u_char *secret);
grad_avp_t *grad_client_decrypt_pairlist(grad_avp_t *plist,
					 u_char *vector, u_char *secret);

/* log.c */
char *rad_print_request(grad_request_t *req, char *outbuf, size_t size);

/* ascend.c */
int grad_ascend_parse_filter(grad_avp_t *pair, char **errp);

/* intl.c */
void grad_app_setup();

/* Logging */
/* The category.priority system below is constructed after that
   in <syslog.h> */
   
/* log categories */
#define L_MKCAT(n)       ((n)<<3)
#define L_MAIN           L_MKCAT(1)  /* Main server process */
#define L_AUTH           L_MKCAT(2)  /* Authentication process */
#define L_ACCT           L_MKCAT(3)  /* Accounting process */
#define L_PROXY          L_MKCAT(4)  /* Proxy */
#define L_SNMP           L_MKCAT(5)  /* SNMP process */
#define L_NCAT           8           /* Number of categories */
#define L_CATMASK        0x38        /* Mask to extract category part */

/* log priorities */
#define L_EMERG    0    /* system is unusable */
#define L_ALERT    1    /* action must be taken immediately */
#define L_CRIT     2    /* critical conditions */
#define L_ERR      3    /* error conditions */
#define L_WARN     4    /* warning conditions */
#define L_NOTICE   5    /* normal but signification condition */
#define L_INFO     6    /* informational */
#define L_DEBUG    7    /* debug-level messages */
#define L_PRIMASK  0x0007  /* mask to extract priority part */

#define L_CAT(v)   (((v)&L_CATMASK)>>3)
#define L_PRI(v)   ((v)&L_PRIMASK)
#define L_MASK(pri) (1<<(pri))
#define L_UPTO(pri) ((1<<((pri)+1))-1)
/* Additional flags */
#define L_PERROR  0x8000

#define GRAD_MKSTRING(x) #x 
#define grad_insist(cond) \
 ((void) ((cond) || \
 __grad_insist_failure(GRAD_MKSTRING(cond), __FILE__, __LINE__)))
#define grad_insist_fail(str) \
 __grad_insist_failure(GRAD_MKSTRING(str), __FILE__, __LINE__)

/* Function prototypes */
typedef void (*grad_logger_fp) (int lvl,
				const grad_request_t *req,
				const grad_locus_t *loc,
				const char *func_name,
				int en,
				const char *fmt,
				va_list ap);
grad_logger_fp grad_set_logger(grad_logger_fp fp);
void grad_app_logger(int level,
		     const grad_request_t *req,
		     const grad_locus_t *loc,
		     const char *func_name, int en,
		     const char *fmt, va_list ap);

void grad_log(int level, const char *fmt, ...);
int __grad_insist_failure(const char *, const char *, int);
void grad_log_req(int level, grad_request_t *req, const char *fmt, ...);
void grad_log_loc(int lvl, grad_locus_t *loc, const char *msg, ...);

/* Debugging facilities */
#ifndef MAX_DEBUG_LEVEL
# define MAX_DEBUG_LEVEL 100
#endif

#if RADIUS_DEBUG
# define debug_on(level) grad_debug_p(__FILE__, level)
# define debug(level, vlist) \
   if (grad_debug_p(__FILE__, level)) \
    _debug_print(__FILE__, __LINE__, __FUNCTION__, _debug_format_string vlist)
#else
# define debug_on(level) 0
# define debug(mode,vlist)
#endif

int grad_debug_p(char *name, int level);
void _debug_print(char *file, size_t line, char *func_name, char *str);
char *_debug_format_string(char *fmt, ...);
const char *grad_request_code_to_name(int code);
int grad_request_name_to_code(const char *);
void set_debug_levels(char *str);
int set_module_debug_level(char *name, int level);
void clear_debug();

const char *grad_next_matching_code_name(void *data);
const char *grad_first_matching_code_name(const char *name, void **ptr);


/* sysdep.h */
int grad_set_nonblocking(int fd);
int grad_max_fd();
grad_uint32_t grad_first_ip();

/* Loadable Modules Suppert */
#define __s_cat3__(a,b,c) a ## b ## c
#define RDL_EXPORT(module,name) __s_cat3__(module,_LTX_,name)

typedef int (*rdl_init_t) (void);
typedef void (*rdl_done_t) (void);

#endif /* !_gnu_radius_radius_h */
