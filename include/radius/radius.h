/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2006,2007,2008 Free Software Foundation, Inc.

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

/* Length of an IPv4 address in 'dotted-quad' representation including
   null terminator */
#define GRAD_IPV4_STRING_LENGTH        16

/* Length of a RADIUS request authenticator */
#define GRAD_AUTHENTICATOR_LENGTH      16
/* Length of an MD5 digest */
#define GRAD_MD5_DIGEST_LENGTH         16
/* Maximum length of a string that can be carried by a RADIUS A/V pair */
#define GRAD_STRING_LENGTH            253
/* Length of a CHAP digest string */ 
#define GRAD_CHAP_VALUE_LENGTH         16

typedef struct {
        u_char code;            /* Request code (see RT_ macros below)*/ 
        u_char id;              /* Request ID */
        u_short length;         /* Request length */ 
        u_char authenticator[GRAD_AUTHENTICATOR_LENGTH];
	                        /* Request authenticator */
} grad_packet_header_t;

/* Radius data types */
#define GRAD_TYPE_INVALID              -1
#define GRAD_TYPE_STRING                0
#define GRAD_TYPE_INTEGER               1
#define GRAD_TYPE_IPADDR                2
#define GRAD_TYPE_DATE                  3

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
	grad_operator_invalid                /* Invalid operator */
#define GRAD_NUM_OPERATORS grad_operator_invalid /* number of operators */
};

/* ************************** Data structures ****************************** */

#define GRAD_MAX_DICTNAME  32
#define GRAD_MAX_SECRETLEN 32
#define GRAD_MAX_REALMNAME 256
#define GRAD_MAX_LONGNAME  256
#define GRAD_MAX_SHORTNAME 32

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
#define GRAD_AP_ADD_REPLACE   0
#define GRAD_AP_ADD_APPEND    1
#define GRAD_AP_ADD_NONE      2

/* Encryption bits */
#define GRAD_AP_ENCRYPT_RFC2138 0x4 /* Encrypted per RFC 2138 */
#define GRAD_AP_ENCRYPT_RFC2868 0x8 /* Encrypted per RFC 2868 */

#define GRAD_AP_ENCRYPT (GRAD_AP_ENCRYPT_RFC2138|GRAD_AP_ENCRYPT_RFC2868)

#define GRAD_AP_PROPAGATE     0x10 /* Propagate attribute through the proxy
				      chain */
#define GRAD_AP_INTERNAL      0x20 /* Internal attribute. */
#define GRAD_AP_BINARY_STRING 0x40 /* Binary string value. No str..()
				      functions should be used */
#define GRAD_AP_TRANSLATE     0x80 /* Attribute has dictionary translations */
				 
#define GRAD_AP_USER_FLAG(n) (0x4000<<(n))

#define GRAD_GET_ADDITIVITY(val) ((val) & 0x3)
#define GRAD_SET_ADDITIVITY(val,a) ((val) = ((val) & ~0x3) | (a))

/* Configuration files types */
#define GRAD_CF_USERS      0
#define GRAD_CF_HINTS      1
#define GRAD_CF_HUNTGROUPS 2
#define GRAD_CF_MAX        3

#define GRAD_AF_LHS(cf) (0x0100<<(cf))
#define GRAD_AF_RHS(cf) (0x0800<<(cf))

#define GRAD_AF_DEFAULT_FLAGS (GRAD_AF_LHS(0)|GRAD_AF_LHS(1)|GRAD_AF_LHS(2)\
                               |GRAD_AF_RHS(0)|GRAD_AF_RHS(1)|GRAD_AF_RHS(2))
#define GRAD_AP_DEFAULT_ADD   GRAD_AP_ADD_APPEND


#define GRAD_PORT_AUTH 0
#define GRAD_PORT_ACCT 1
#define GRAD_PORT_MAX  2

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
        int    port[GRAD_PORT_MAX];  /* Ports to use */
        char   *secret;         /* Shared secret */
	off_t  id_offset;       /* Offset of the grad_server_id_t in the id
				   file */
};

typedef struct {
        grad_uint32_t source_ip; /* Source IP address for xmits */
        unsigned timeout;        /* Amount of time to wait for the response */
        unsigned retries;        /* Number of re-sends to each server before
				    giving up */
	size_t buffer_size;      /* Size of the recv buffer */
        grad_list_t   *servers;  /* List of servers */
} grad_server_queue_t;    

struct grad_value_pair;
typedef int (*grad_attr_parser_fp)(struct grad_value_pair *p, char **s);

/* Dictionary attribute */

typedef struct dict_attr grad_dict_attr_t;
struct dict_attr {
        char   *name;          /* Attribute name */
	int    value;          /* Attribute value */
	int    type;           /* Data type */
	int    vendor;         /* Vendor index */
	int    prop;           /* Properties */
	grad_attr_parser_fp parser; /* Not-NULL for "abinary" */
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

/* Attribute evaluation type */
enum grad_avp_eval_type {
	grad_eval_const,     /* Value is a constant */  
	grad_eval_interpret, /* avp_strvalue contains a Rewrite expression that
				must be interpreted */
	grad_eval_compiled   /* avp_strvalue contains a symbolic name of a
				compiled Rewrite expression. Use rewrite_eval()
				to evaluate it */
};

typedef struct grad_string {
	size_t size;
	char *data;
} grad_string_t;

typedef union grad_datum {
	grad_uint32_t   ival;       /* integer value */
	grad_string_t   sval;       /* string value */
} grad_datum_t;

/* An attribute/value pair */
typedef struct grad_value_pair {
        struct grad_value_pair  *next;      /* Link to next A/V pair in list */
        char                    *name;      /* Attribute name */
        int                     attribute;  /* Attribute value */
        int                     type;       /* Data type */
        enum grad_avp_eval_type eval_type;  /* Evaluation flag */
        int                     prop;       /* Properties */ 
        enum grad_operator operator;        /* Comparison operator */
	grad_datum_t            datum;      /* Actual data */

#define avp_lvalue datum.ival
#define avp_strvalue datum.sval.data
#define avp_strlength datum.sval.size

} grad_avp_t;

typedef struct grad_nas {
	grad_netdef_t netdef;
        char longname[GRAD_MAX_LONGNAME+1];
        char shortname[GRAD_MAX_SHORTNAME+1];
        char nastype[GRAD_MAX_DICTNAME+1];
        grad_envar_t *args;
        void *app_data;
} grad_nas_t;

typedef struct grad_realm {
        char realm[GRAD_MAX_REALMNAME+1];
	grad_envar_t *args;
	grad_server_queue_t *queue;
} grad_realm_t;

typedef struct grad_request {
        grad_uint32_t ipaddr;       /* Source IP address */
        u_short       udp_port;     /* Source port */
        u_char        id;           /* Request identifier */
        u_char        code;         /* Request code */
        u_char        authenticator[GRAD_AUTHENTICATOR_LENGTH];
	                            /* Request authenticator */
        u_char        *secret;      /* Shared secret */
        grad_avp_t    *avlist;      /* Request pairs */
} grad_request_t;

typedef struct grad_keyword grad_keyword_t;
struct grad_keyword {
        char *name;
        int tok;
};

typedef struct grad_matching_rule grad_matching_rule_t;
struct grad_matching_rule {
        char *name;
        grad_avp_t *lhs;
        grad_avp_t *rhs;
	grad_locus_t loc;
};

/* External variables */

extern char *grad_config_dir;
extern char *grad_log_dir;
extern char *grad_acct_dir;
extern char *grad_utmp_file;
extern char *grad_wtmp_file;
extern char *grad_stat_file;
extern char *grad_msgid_file;
extern char *grad_pid_dir;
extern char *grad_bug_report_address;
extern int grad_source_info_option;

/* Parser */
extern grad_locus_t grad_parser_source_locus;

int grad_parser_lex_init(char *name);
void grad_parser_lex_finish();
int grad_parser_lex_sync();

#define GRAD_NITEMS(a) sizeof(a)/sizeof((a)[0])

size_t grad_create_pdu(void **rptr, int code, int id,
		       u_char *authenticator, u_char *secret,
		       grad_avp_t *pairlist, char *msg);

grad_request_t *grad_decode_pdu(grad_uint32_t host,
				u_short udp_port, u_char *buffer,
				size_t length);

int grad_server_send_reply(int fd, grad_request_t *radreq,
			   int reply_code, grad_avp_t *reply_pairs,
			   char *reply_msg);
int grad_server_send_challenge(int fd, grad_request_t *radreq,
			       grad_avp_t *reply_pairs, char *msg,
			       char *state);


/* dict.c */
#define GRAD_VENDOR_CODE(x) (x >> 16)
#define GRAD_VSA_ATTR_NUMBER(attrno,code) ((attrno) | (code) << 16)

int grad_dict_init();
void grad_dict_free();
grad_dict_attr_t *grad_attr_number_to_dict(int);
grad_dict_attr_t *grad_attr_name_to_dict(const char *);
grad_dict_value_t *grad_value_name_to_value(const char *, int);
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
	
extern int grad_resolve_hostnames;

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
int grad_xlat_keyword(grad_keyword_t *kw, const char *str, int def);
int grad_astrcat(char **pptr, ...);

struct timeval;
int grad_recompute_timeout(struct timeval *start, struct timeval *tval);

/* c-strcase.c */
int grad_c_strcasecmp(const char *a, const char *b);
int grad_c_strncasecmp(const char *a, const char *b, size_t n);

/* cryptpass.c */
void grad_encrypt_password(grad_avp_t *pair, char *password,
			   char *authenticator, char *secret);
void grad_decrypt_password(char *password, grad_avp_t *pair,
			   char *authenticator, char *secret);
void grad_decrypt_password_broken(char *password, grad_avp_t *pair,
				  char *authenticator, char *secret);
void grad_encrypt_tunnel_password(grad_avp_t *pair, u_char tag, char *password,
				  char *authenticator, char *secret);
void grad_decrypt_tunnel_password(char *password, u_char *tag,
				  grad_avp_t *pair,
				  char *authenticator, char *secret);

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
void grad_client_random_authenticator(char *authenticator);
grad_avp_t *grad_client_encrypt_pairlist(grad_avp_t *plist,
					 u_char *authenticator, u_char *secret);
grad_avp_t *grad_client_decrypt_pairlist(grad_avp_t *plist,
					 u_char *authenticator, u_char *secret);

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
#define GRAD_LOG_MKCAT(n)       ((n)<<3)
#define GRAD_LOG_MAIN           GRAD_LOG_MKCAT(1)  /* Main server process */
#define GRAD_LOG_AUTH           GRAD_LOG_MKCAT(2)  /* Authentication process */
#define GRAD_LOG_ACCT           GRAD_LOG_MKCAT(3)  /* Accounting process */
#define GRAD_LOG_PROXY          GRAD_LOG_MKCAT(4)  /* Proxy */
#define GRAD_LOG_SNMP           GRAD_LOG_MKCAT(5)  /* SNMP process */
#define GRAD_LOG_NCAT           8           /* Number of categories */
#define GRAD_LOG_CATMASK        0x38        /* Mask to extract category part */

/* log priorities */
#define GRAD_LOG_EMERG    0    /* system is unusable */
#define GRAD_LOG_ALERT    1    /* action must be taken immediately */
#define GRAD_LOG_CRIT     2    /* critical conditions */
#define GRAD_LOG_ERR      3    /* error conditions */
#define GRAD_LOG_WARN     4    /* warning conditions */
#define GRAD_LOG_NOTICE   5    /* normal but signification condition */
#define GRAD_LOG_INFO     6    /* informational */
#define GRAD_LOG_DEBUG    7    /* debug-level messages */
#define GRAD_LOG_PRIMASK  0x0007  /* mask to extract priority part */

#define GRAD_LOG_CAT(v)   (((v)&GRAD_LOG_CATMASK)>>3)
#define GRAD_LOG_PRI(v)   ((v)&GRAD_LOG_PRIMASK)
#define GRAD_LOG_MASK(pri) (1<<(pri))
#define GRAD_LOG_UPTO(pri) ((1<<((pri)+1))-1)
/* Additional flags */
#define GRAD_LOG_PERROR  0x8000

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
void grad_default_logger(int level,  const grad_request_t *req,
			 const grad_locus_t *loc,
			 const char *func_name, int en,
			 const char *fmt, va_list ap);

void grad_log(int level, const char *fmt, ...);
int __grad_insist_failure(const char *, const char *, int);
void grad_log_req(int level, grad_request_t *req, const char *fmt, ...);
void grad_log_loc(int lvl, grad_locus_t *loc, const char *msg, ...);

/* sysdep.h */
int grad_set_nonblocking(int fd);
int grad_max_fd();
grad_uint32_t grad_first_ip();

/* Loadable Modules Suppert */
#define __s_cat3__(a,b,c) a ## b ## c
#define GRAD_DL_EXPORT(module,name) __s_cat3__(module,_LTX_,name)

typedef int (*grad_dl_init_t) (void);
typedef void (*grad_dl_done_t) (void);

/* slist.c */
#define GRAD_SLIST_BUCKET_SIZE 1024

typedef struct grad_slist *grad_slist_t;

grad_slist_t grad_slist_create(void);
void grad_slist_clear(grad_slist_t slist);
void grad_slist_free(grad_slist_t *slist);
void grad_slist_append(grad_slist_t slist, void *str, size_t n);
void grad_slist_append_char(grad_slist_t slist, char c);
size_t grad_slist_size(grad_slist_t slist);
size_t grad_slist_coalesce(grad_slist_t slist);
void *grad_slist_finish(grad_slist_t slist);
void *grad_slist_head(grad_slist_t slist, size_t *psize);
void grad_slist_grow_backslash_num(grad_slist_t slist, char *text, char **pend,
				   int len, int base);
void grad_slist_grow_backslash(grad_slist_t slist, char *text, char **endp);

/* *tostr.c */
size_t grad_inttostr(int, char *, size_t);
size_t grad_longtostr(int, char *, size_t);
size_t grad_offtostr(int, char *, size_t);
size_t grad_sizetostr(int, char *, size_t);
size_t grad_uinttostr(int, char *, size_t);
size_t grad_ulongtostr(int, char *, size_t);

#endif /* !_gnu_radius_radius_h */
