#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sysdep.h>
#include <radius.h>
#include <radutmp.h>
#include <radlast.h>

#include <asn1.h>
#include <snmp.h>
#include <radsnmp.h>
#include <radmibs.h>

#ifndef offsetof
# define offsetof(s,m) (off_t)(&((s*)0)->m)
#endif

typedef int (*sess_handler_t)(struct snmp_var *, void*);

typedef struct {
        oid_t oid;
        void *closure;
} SNMP_GET_TAB;

typedef struct {
        oid_t oid;
        off_t offset;
} SNMP_WALK_TAB;

struct nas_usage {
        struct nas_usage *next;
        grad_uint32_t ipaddr;
        char *ident;
        counter ports_active;
        counter ports_idle;
        Auth_server_stat auth;
        Acct_server_stat acct;
};

struct port_session {
        time_t start;
        struct timeval duration;
};

struct port_usage {
        struct port_usage *next;
        int nas_index;             /* Index of the corresponding NAS */
        int port_no;               /* port number */
        int active;                /* is the port used now */
        char *login;               /* last login name */
        grad_uint32_t framed_address;      /* IP address assigned to that port */
        unsigned long count;       /* number of logins */
        time_t start;
        time_t lastin;             /* last time the user logged in */
        time_t lastout;            /* last time the user logged out */
        
        struct timeval inuse;      /* total time the line was in use */
        struct timeval idle;       /* total idle time */

        struct port_session maxinuse;
        struct port_session maxidle;
};      

extern char *hostname;
extern char *community;
extern int port;

char *stat_ident;
serv_stat stat_config_reset;
counter stat_total_lines;
counter stat_lines_in_use;
counter stat_lines_idle;
