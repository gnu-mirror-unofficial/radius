/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
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
#include <raddict.h>
#include <log.h>
#include <mem.h>

#define DOTTED_QUAD_LEN         16

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_DIGEST_LEN		16
#define AUTH_STRING_LEN	       253

typedef struct pw_auth_hdr {
	u_char		code;
	u_char		id;
	u_short		length;
	u_char		vector[AUTH_VECTOR_LEN];
	u_char		data[2];
} AUTH_HDR;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#ifndef DEF_AUTH_PORT
# define DEF_AUTH_PORT	1645
#endif
#ifndef DEF_ACCT_PORT
# define DEF_ACCT_PORT  1646
#endif

#define TYPE_INVALID                -1
#define TYPE_STRING			0
#define TYPE_INTEGER			1
#define TYPE_IPADDR			2
#define TYPE_DATE			3

#define	RT_AUTHENTICATION_REQUEST	1
#define	RT_AUTHENTICATION_ACK		2
#define	RT_AUTHENTICATION_REJECT	3
#define	RT_ACCOUNTING_REQUEST		4
#define	RT_ACCOUNTING_RESPONSE		5
#define	RT_ACCOUNTING_STATUS		6
#define RT_PASSWORD_REQUEST		7
#define RT_PASSWORD_ACK			8
#define RT_PASSWORD_REJECT		9
#define	RT_ACCOUNTING_MESSAGE		10
#define RT_ACCESS_CHALLENGE		11

#define RT_ASCEND_TERMINATE_SESSION     31
#define RT_ASCEND_EVENT_REQUEST         33
#define RT_ASCEND_EVENT_RESPONSE        34
/* These two are not implemented yet */
#define RT_ASCEND_ALLOCATE_IP           51
#define RT_ASCEND_RELEASE_IP            52


#define DV_ACCT_STATUS_TYPE_QUERY       -1

/* Basic structures */

enum {
	OPERATOR_EQUAL = 0,             /* = */
	OPERATOR_NOT_EQUAL,	        /* != */
	OPERATOR_LESS_THAN,	        /* < */
	OPERATOR_GREATER_THAN,	        /* > */
	OPERATOR_LESS_EQUAL,	        /* <= */
	OPERATOR_GREATER_EQUAL,	        /* >= */
	NUM_OPERATORS                   /* number of operators */
};

/* ************************** Data structures ****************************** */

#define MAX_DICTNAME  32
#define MAX_SECRETLEN 32
#define MAX_REALMNAME 256
#define MAX_LONGNAME  256
#define MAX_SHORTNAME 32

/* Attribute properties */
#define AP_ADD_REPLACE   0
#define AP_ADD_APPEND    1
#define AP_ADD_NONE      2

#define AP_PROPAGATE   0x10

#define ADDITIVITY(val) ((val) & 0x3)
#define SET_ADDITIVITY(val,a) ((val) = ((val) & ~0x3) | (a))

/* Configuration files types */
#define CF_USERS      0
#define CF_HINTS      1
#define CF_HUNTGROUPS 2
#define CF_MAX        3

#define AF_CHECKLIST(cf) (0x0100<<(2*cf))
#define AF_REPLYLIST(cf) (0x0200<<(2*cf))

#define AF_DEFAULT_FLAGS (AF_CHECKLIST(0)|AF_CHECKLIST(1)|AF_CHECKLIST(2)\
			 |AF_REPLYLIST(0)|AF_REPLYLIST(1)|AF_REPLYLIST(2))
#define AP_DEFAULT_ADD   AP_ADD_APPEND


/* Dictionary attribute */
typedef struct dict_attr {
        struct dict_attr        *next;      /* Link to the next attribute */
        char                    *name;      /* Attribute name */
        int                     value;      /* Attribute value */
        int                     type;       /* Data type */
        int                     vendor;     /* Vendor index */
        int                     prop;       /* Properties */
} DICT_ATTR;

/* Dictionary value */
typedef struct dict_value {
	struct dict_value	*next;
	char			*name;
	DICT_ATTR               *attr;
	int			value;
} DICT_VALUE;

/* Dictionary vendor information */
typedef struct dict_vendor {
	struct dict_vendor	*next;
	char			*vendorname;
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
	int                     prop;       /* Properties */ 
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
	UINT4			ipaddr;       /* Source IP address */
	u_short			udp_port;     /* Source port */
	u_char			id;           /* Request identifier */
	u_char			code;         /* Request code */
	u_char			vector[AUTH_VECTOR_LEN]; /* Rq authenticator */
	u_char			*secret;      /* Shared secret */
	VALUE_PAIR		*request;     /* Request pairs */
	u_char			*data;	      /* Raw received data */
	int			data_len;     /* Length of raw data */
	int                     data_alloced; /* Was the data malloced */
        /* Proxy support fields */
	char			*realm;       /* stringobj, actually */
	int			validated;    /* Already md5 checked */
	UINT4			server_ipaddr;
	UINT4			server_id;
	VALUE_PAIR		*server_reply;/* Reply from other server */
	int			server_code;  /* Reply code from other srv */
} RADIUS_REQ;

struct envar_t;

typedef struct nas {
	struct nas		*next;
	UINT4			ipaddr;
	char			longname[MAX_LONGNAME+1];
	char			shortname[MAX_SHORTNAME+1];
	char			nastype[MAX_DICTNAME+1];
	struct envar_t          *args;
	void                    *app_data;
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

struct keyword {
	char *name;
	int tok;
};

/* External variables */

extern char *progname;
extern char *radius_dir;
extern char *radlog_dir;
extern char *radacct_dir;
extern char *radutmp_path;
extern char *radwtmp_path;
extern char *radstat_path;
extern char *radpid_dir;
extern char *bug_report_address;


/* dict.c */
#define VENDOR(x) (x >> 16)

int dict_init();
DICT_ATTR *attr_number_to_dict(int);
DICT_ATTR *attr_name_to_dict(char *);
DICT_VALUE *value_name_to_value(char *, int);
DICT_VALUE *value_lookup(UINT4, char *);
int vendor_id_to_pec(int);
int vendor_pec_to_id(int);
char *vendor_pec_to_name(int);
int vendor_name_to_id(char *);


/* md5.c */

void md5_calc(u_char *, u_char *, u_int);
/* md5crypt.c */
char *md5crypt(const char *pw, const char *salt);

/* avl.c */
VALUE_PAIR *avp_alloc();
void avp_free();
void avl_free(VALUE_PAIR *);
VALUE_PAIR *avl_find(VALUE_PAIR *, int);
void avl_delete(VALUE_PAIR **, int);
void avl_add_list(VALUE_PAIR **, VALUE_PAIR *);
void avl_add_pair(VALUE_PAIR **, VALUE_PAIR *);
VALUE_PAIR *avl_dup(VALUE_PAIR *from);
VALUE_PAIR *avp_dup(VALUE_PAIR *vp);
void avl_merge(VALUE_PAIR **dst_ptr, VALUE_PAIR **src_ptr);
VALUE_PAIR *avp_create(int attr, int length, char *strval, int lval);
void avl_move_attr(VALUE_PAIR **to, VALUE_PAIR **from, int attr);
void avl_move_pairs(VALUE_PAIR **to, VALUE_PAIR **from,
		    int (*fun)(), void *closure);

extern int do_not_resolve;
char *ip_hostname (UINT4);
UINT4 get_ipaddr (char *);
int good_ipaddr(char *);
char *ipaddr2str(char *, UINT4);
UINT4 ipstr2long(char *);

/* nas.c */
NAS *nas_next(NAS *p);
int nas_read_file(char *file);
NAS *nas_lookup_name(char *name);
NAS *nas_lookup_ip(UINT4 ipaddr);
char *nas_ip_to_name(UINT4 ipaddr);
NAS *nas_request_to_nas(RADIUS_REQ *radreq);
char *nas_request_to_name(RADIUS_REQ *radreq);

/* fixalloc.c */
#define Alloc_entry(t) alloc_entry(sizeof(t))
RADIUS_REQ *radreq_alloc();
#define free_request free_entry

/* raddb.c */
int read_raddb_file(char *name, int vital, int (*fun)(), void *closure);

/* mem.c */
void *emalloc(size_t);
void efree(void*);
char *estrdup(char *);

/* radpaths.c */
void radpath_init();

/* users.y */
int parse_file(char *file, void *c, int (*f)());
int user_gettime(char *valstr, struct tm *tm);
VALUE_PAIR *install_pair(char *name, int op, char *valstr);


/* util.c */
struct passwd *rad_getpwnam(char *);
void radreq_free(RADIUS_REQ *radreq);
void rad_lock(int fd, size_t size, off_t off, int whence);
void rad_unlock(int fd, size_t size, off_t off, int whence);
char *mkfilename(char *, char*);
char *mkfilename3(char *dir, char *subdir, char *name);
int backslash(int c);
void string_copy(char *d, char *s, int  len);
#define STRING_COPY(s,d) string_copy(s,d,sizeof(s)-1)
char *format_pair(VALUE_PAIR *pair);
char *format_ipaddr(UINT4 ipaddr);
void debug_pair(char *prefix, VALUE_PAIR *pair);
int format_string_visual(char *buf, int runlen, char *str, int len);

/* cryptpass.c */
void encrypt_password(VALUE_PAIR *pair, char *password,
		      char *vector, char *secret);
void decrypt_password(char *password, VALUE_PAIR *pair,
		      char *vector, char *secret);
void decrypt_password_broken(char *password, VALUE_PAIR *pair,
			     char *vector, char *secret);

