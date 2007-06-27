/*
   This file is part of GNU Radius SNMP Library.
   Copyright (C) 2001,2007 Free Software Foundation, Inc.
   Written by Sergey Poznyakoff

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

typedef u_int ip_addr_t;

#define SNMP_PORT 161
#define SNMP_PACKET_LENGTH 4500

/* error definitions */
#define E_ASN_ENCODE       1
#define E_ASN_DECODE       2
#define E_SNMP_NOMEM       3
#define E_SNMP_BAD_OID     4
#define E_SNMP_BAD_ADDRESS 5
#define E_SNMP_SOCKET      6
#define E_SNMP_BIND        7
#define E_SNMP_SEND        8
#define E_SNMP_NOT_SUPPORTED 9
#define E_SNMP_DECODE      10
#define E_SNMP_BAD_VERSION 11
#define E_SNMP_UNKNOWN_REQ 12
#define E_SNMP_BAD_VARTYPE 13

extern int * __snmp_errno_location();
#define snmp_errno (*__snmp_errno_location())
#define SNMP_SET_ERRNO(e) snmp_errno = (e)

#define SMI_INTEGER     ASN_INTEGER
#define SMI_STRING      ASN_OCTET_STR
#define SMI_OBJID       ASN_OBJECT_ID
#define SMI_NULLOBJ     ASN_NULL
#define SMI_IPADDRESS   ASN_IPADDRESS
#define SMI_COUNTER32   ASN_COUNTER
#define SMI_GAUGE32     ASN_GAUGE
#define SMI_UNSIGNED32  SMI_GAUGE32
#define SMI_TIMETICKS   ASN_TIMETICKS
#define SMI_OPAQUE      ASN_OPAQUE
#define SMI_COUNTER64   ASN_COUNTER64

/* PDU types */
#define SNMP_PDU_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0)
#define SNMP_PDU_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1)
#define SNMP_PDU_RESPONSE   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2)
#define SNMP_PDU_SET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3)
#define SNMP_MSG_TRAP       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)

/* PDU error values */
#define SNMP_ERR_NOERROR             0x0
#define SNMP_ERR_TOOBIG              0x1
#define SNMP_ERR_NOSUCHNAME          0x2
#define SNMP_ERR_BADVALUE            0x3
#define SNMP_ERR_READONLY            0x4
#define SNMP_ERR_GENERR              0x5
#define SNMP_ERR_NOACCESS            0x6
#define SNMP_ERR_WRONGTYPE           0x7
#define SNMP_ERR_WRONGLENGTH         0x8
#define SNMP_ERR_WRONGENCODING       0x9
#define SNMP_ERR_WRONGVALUE          0x10
#define SNMP_ERR_NOCREATION          0x11
#define SNMP_ERR_INCONSISTENTVALUE   0x12
#define SNMP_ERR_RESOURCEUNAVAILABLE 0x13
#define SNMP_ERR_COMMITFAILED        0x14
#define SNMP_ERR_UNDOFAILED          0x15
#define SNMP_ERR_AUTHORIZATIONERROR  0x16
#define SNMP_ERR_NOTWRITABLE         0x17
#define SNMP_ERR_INCONSISTENTNAME    0x18

/* Versions */
#define SNMP_VERSION_1 0

/* variable */
struct snmp_var {
        struct snmp_var *next;
        oid_t name;
        int val_length;
        u_char type;
        union {
                int i;
                u_char *s;
                oid_t o;
        } v;
#define var_int v.i
#define var_str v.s
#define var_oid v.o
};

struct snmp_pdu {
        u_char type;
        struct sockaddr_in peer_sin; /*??*/
        int req_id;
        int err_stat;
        int err_ind;
        struct snmp_var *var;
};

/* request list */
struct snmp_request {
        struct snmp_request *next;
        int retries;           /* number of retries this request already
                                  suffered */
        int timeout;           /* timeout for next retry */
        struct timeval expire; /* when this request will expire */
        struct snmp_pdu *pdu;  /* PDU of the request */
};

#define SNMP_CONV_TIMEOUT            0
#define SNMP_CONV_RECV_MSG           1
#define SNMP_CONV_COMMUNITY_MISMATCH 2

struct snmp_session;

typedef int (*snmp_cfn)(int type, struct snmp_session *sp, struct snmp_pdu *pdu, void *closure);

struct snmp_session {
        struct snmp_session *next;

        int version;
        struct {
                u_char *str;
                int len;
        } community;
        int retries;
        int timeout;
        char *remote_host;
        u_short remote_port;
        u_short local_port;
        int sd;
        struct sockaddr_in local_sin;
        struct sockaddr_in remote_sin;
        
        snmp_cfn converse;
        void *app_closure;

        struct snmp_pdu *pdu;
        struct snmp_request *request_list;  /* list of outstanding requests */
};

typedef void *(*snmp_alloc_t)(size_t);
typedef void *(*snmp_free_t)(void*);

void *snmp_alloc(size_t);
void snmp_free(void*);
char *snmp_strdup(char *str);

void snmp_init(int retries, int timeout,
               snmp_alloc_t memalloc, snmp_free_t memfree);

oid_t oid_dup(oid_t oid);
oid_t oid_create(int len);
oid_t oid_create_from_string(char *str);
oid_t oid_create_from_subid(int len, subid_t *subid);
int oid_cmp(oid_t a, oid_t b);

char * sprint_oid(char *buf, int buflen, oid_t oid);

struct snmp_pdu *snmp_pdu_create(int type);
void snmp_pdu_free(struct snmp_pdu *pdu);
void snmp_pdu_add_var(struct snmp_pdu *pdu, struct snmp_var *var);
u_char *snmp_pdu_encode(u_char *data, int *length, struct snmp_pdu *pdu);
u_char *snmp_pdu_decode(u_char *data, int *length, struct snmp_pdu *pdu);

int snmp_send(struct snmp_session *sess, struct snmp_pdu *pdu);
int snmp_request_xmit(struct snmp_session *sess, struct snmp_request *req);

int snmp_req_id(void);
struct snmp_session *snmp_session_create(char *community, char *host,
                                         int port, snmp_cfn cfn,
                                         void *closure);
int snmp_session_open(struct snmp_session *sp, ip_addr_t local_ip,
                      int local_port, int timeout, int retries);
void snmp_session_close(struct snmp_session *sess);
void snmp_session_free(struct snmp_session *sess);

void snmp_var_free(struct snmp_var *var);
void snmp_var_free_list(struct snmp_var *var);
struct snmp_var *snmp_var_create(oid_t oid);
struct snmp_var *snmp_var_dup(struct snmp_var *src);
struct snmp_var *snmp_var_dup_list(struct snmp_var *var);
u_char *snmp_var_encode(u_char *data, int *length, struct snmp_var *var,
                        int version);
u_char *snmp_var_decode(u_char *data, int *length, struct snmp_var **var,
                        int version);

int snmp_encode_request(struct snmp_session *sess, struct snmp_pdu *pdu,
                        u_char *packet_buf, int  *length);
int snmp_decode_request(struct snmp_session *sess, struct snmp_pdu *pdu,
                        u_char *packet, int length, char *comm, int *comm_len);

void snmp_poll(struct snmp_session *sess);
int snmp_query(struct snmp_session *sess, struct snmp_pdu *pdu);
void snmp_timeout(struct snmp_session *sess);
void snmp_read(struct snmp_session *sess, fd_set *fdset);

char *snmp_strerror(int en);
