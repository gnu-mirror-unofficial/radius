/* This file is part of GNU Radius.
   Copyright (C) 2002,2003 Sergey Poznyakoff
  
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

/* Support for ascend binary filters. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <radiusd.h>
#include <argcv.h>

enum ascend_filter_type {
	ascend_filter_generic,      /* 0 */
	ascend_filter_ip,           /* 1 */
	ascend_filter_ipx           /* 2 */
};

/* Maximum compare length for Generic filters. */
#define ASCEND_MAX_CMP_LENGTH 6

enum ascend_filter_cmp_op {
	ascend_cmp_none,
	ascend_cmp_lt,
	ascend_cmp_eq,
	ascend_cmp_gt,
	ascend_cmp_ne
};

/* The format of an IP filter attribute value. Fields are in netorder */
typedef struct {
	UINT4    src_ip;       /* The source IP address.  */
	UINT4    dst_ip;       /* The destination IP address.  */
	u_char   src_masklen;  /* The source netmask length */
	u_char   dst_masklen;  /* The destination netmask length */
	u_char   proto;        /* The IP protocol number */
	u_char   established;  /* True if the filter matches only packets
				  with established state of a TCP
				  connection. */
	u_short  src_port;     /* The source port number */
	u_short  dst_port;     /* The destination port number */
	u_char   src_cmp;      /* Comparison operator for source port */
	u_char   dst_cmp;      /* Comparison operator for dest port */
} ASCEND_FILTER_IP;

/* IPX stuff. Not used at the moment */
#define IPX_NODE_ADDR_LEN 6

typedef UINT4   IPXADDR;
typedef char    IPXNODE[IPX_NODE_ADDR_LEN];
typedef u_short IPXSOCKET;

typedef struct {
	IPXADDR   src_addr;    /* Source IPX Net address */ 
	IPXNODE   src_node;    /* Source IPX Node address */
	IPXSOCKET src_socket;  /* Source IPX socket address */
	IPXADDR   dst_addr;    /* Destination Net address */   
	IPXNODE   dst_node;    /* Destination Node address */  
	IPXSOCKET dst_socket;  /* Destination socket address */
	u_char    src_cmp;     /* Comparison operator for source socket */
	u_char    dst_cmp;     /* Comparison operator for dest socket */
} ASCEND_FILTER_IPX;

/* generic filter */
typedef struct {
	u_short   offset;      /* Offset in the packet to start comparison
				  from */
	u_short   len;         /* Number of bytes to compare */
	u_short   more;        /* If true, the next filter is also to be
				  applied to the packet */
	u_char    mask[ASCEND_MAX_CMP_LENGTH];
                               /* A bitmask specifying the bits to compare */
	        
	u_char    value[ASCEND_MAX_CMP_LENGTH];
                               /* A value to compare against the masked
				  bits in the packet */
	u_char    neq;         /* True if comparison op is != */
} ASCEND_FILTER_GENERIC;

typedef struct {
	u_char type;           /* Filter type from ascend_filter_type */ 
	u_char forward;        /* True if the matching packet is to be
				  forwarded. */
	u_char input;          /* True if this is an input filter */
	u_char unused;
	union {                /* A filter itself: */
		ASCEND_FILTER_IP  ip;
		ASCEND_FILTER_IPX ipx;
		ASCEND_FILTER_GENERIC generic;
		u_char fill[26];
	} v;
} ASCEND_FILTER;


struct ascend_parse_buf {
	int tokc;        /* Number of tokens */
	char **tokv;     /* List of tokens */
	int tokn;        /* Index of the current token */
	ASCEND_FILTER *flt; /* Pointer to filter structure to be filled */
	char **errmsg;   /* Error message */
};

static char *_get_token(struct ascend_parse_buf *pb, int require);
static char *_lookahead(struct ascend_parse_buf *pb);
static int _get_type(struct ascend_parse_buf *pb);
static int _get_dir(struct ascend_parse_buf *pb);
static int _get_action(struct ascend_parse_buf *pb);
static int _get_hex_string(struct ascend_parse_buf *pb, u_char *buf);
static int _ascend_parse_generic(struct ascend_parse_buf *pb);
static int _get_protocol(struct ascend_parse_buf *pb);
static int _get_direction_type(struct ascend_parse_buf *pb, char *suffix, int la);
static int _get_ip(struct ascend_parse_buf *pb);
static int _ascend_parse_ip_clause(struct ascend_parse_buf *pb);
static int _get_op(struct ascend_parse_buf *pb);
static int _get_port(struct ascend_parse_buf *pb);
static int _ascend_parse_port_clause(struct ascend_parse_buf *pb);
static int _ascend_parse_ip(struct ascend_parse_buf *pb);
static int _ascend_parse(struct ascend_parse_buf *pb);
 
/* generic (more or less) calls */
#define _moreinput(pb) ((pb)->tokn < (pb)->tokc)

static char *
_get_token(struct ascend_parse_buf *pb, int require)
{

	if (!_moreinput(pb)) {
		if (require) {
			asprintf(pb->errmsg, _("Unexpected end of string"));
			return NULL;
		}
		return NULL;
	}
	return pb->tokv[pb->tokn++];
}

static char *
_lookahead(struct ascend_parse_buf *pb)
{
	if (_moreinput(pb))
		return pb->tokv[pb->tokn];
	return NULL;
}

static int
_get_type(struct ascend_parse_buf *pb)
{
	char *tok = _get_token(pb, 1);
	if (!tok)
		return 1;
	if (strcmp(tok, "ip") == 0)
		pb->flt->type = ascend_filter_ip;
	else if (strcmp(tok, "ipx") == 0)
		pb->flt->type = ascend_filter_ip;
	else if (strcmp(tok, "generic") == 0)
		pb->flt->type = ascend_filter_generic;
	else {
		asprintf(pb->errmsg, "%s: %s",
			 _("Unknown filter type"), tok);
		return 1;
	}
	return 0;
}

static int
_get_dir(struct ascend_parse_buf *pb)
{
	char *tok;
	if ((tok = _get_token(pb, 1)) == NULL)
		return 1;
	if (strcmp(tok, "in") == 0)
		pb->flt->input = 1;
	else if (strcmp(tok, "out") == 0)
		pb->flt->input = 0;
	else {
		asprintf(pb->errmsg, _("Invalid direction"));
		return 1;
	}
	return 0;
}

static int
_get_action(struct ascend_parse_buf *pb)
{
	char *tok;
	if ((tok = _get_token(pb, 1)) == NULL)
		return 1;
	if (strcmp(tok, "forward") == 0)
		pb->flt->forward = 1;
	else if (strcmp(tok, "drop") == 0)
		pb->flt->forward = 0;
	else {
		asprintf(pb->errmsg, "%s: %s",
			 _("Unknown action"), tok);
		return 1;
	}
	return 0;
}

/* ************************************************************************* */
/* GENERIC filter parsing */

int
_get_hex_string(struct ascend_parse_buf *pb, u_char *buf)
{
	u_char tmp[2*ASCEND_MAX_CMP_LENGTH], *p;
	char *tok = _get_token(pb, 1);
	int len, rc, i;
	
	if (!tok)
		return -1;

	len = strlen(tok);
	if (len > 2*ASCEND_MAX_CMP_LENGTH) {
		asprintf(pb->errmsg, _("Octet string too long"));
		return -1;
	}

	rc = len / 2;
	if (len % 2)
		rc++;

	memset(tmp, 0, sizeof tmp);

	for (p = tmp; len; len--, p++, tok++) {
		if (*tok >= 0 && *tok <= 9)
			*p = *tok - '0';
		else if (isxdigit(*tok)) {
			if (*tok > 'Z')
				*p = *tok - 'a' + 10;
			else
				*p = *tok - 'A' + 10;
		} else {
			asprintf(pb->errmsg,
				 _("Invalid hex character (near %s)"), tok);
			return -1;
		}
	}

	for (i = 0; i < 2*ASCEND_MAX_CMP_LENGTH; i++)
		*buf++ = (tmp[i] << 4) | tmp[i+1];
	return rc;
}

/* Generic filter is:

  "generic" dir action offset mask ["=="|"!="] value [ "more" ]
  where dir    is {"in"|"out"}
        action is {"forward"|"drop"}
	offset is number
	mask and value are hex strings */
   
int
_ascend_parse_generic(struct ascend_parse_buf *pb)
{
	char *p;
	int num;
	char *tok = _get_token(pb, 1);
	int len;
	
	if (!tok)
		return 1;
	num = strtoul(tok, &p, 0);
	if (*p) {
		asprintf(pb->errmsg, "%s: %s",
			 _("Invalid offset"), tok);
		return 1;
	}
	pb->flt->v.generic.offset = ntohs(num);
	if ((len = _get_hex_string(pb, pb->flt->v.generic.mask)) < 0)
		return 1;
	pb->flt->v.generic.len = htons(len);

	tok = _lookahead(pb);
	if (!tok) 
		return 1;

	if (strcmp(tok, "==") == 0) {
		pb->flt->v.generic.neq = 0;
		_get_token(pb, 1);
	} else if (strcmp(tok, "!=") == 0) {
		pb->flt->v.generic.neq = 1;
		_get_token(pb, 1);
	}
	
	if ((num = _get_hex_string(pb, pb->flt->v.generic.value)) < 0)
		return 1;
	if (num != len) {
		asprintf(pb->errmsg,
			 _("Value and mask are not of same size"));
		return 1;
	}
	
	tok = _get_token(pb, 0);
	if (!tok)
		return 0;

	if (strcmp(tok, "more") == 0)
		pb->flt->v.generic.more = 1;
	else {
		asprintf(pb->errmsg,
			 _("Expected `more' but found `%s'"),
			 tok);
		return 1;
	}
	return 0;
}

/* ************************************************************************* */
/* IP filter parsing */
int
_get_protocol(struct ascend_parse_buf *pb)
{
	char *tok = _get_token(pb, 1);
	char *p;
	int num;
	
	num = strtoul(tok, &p, 0);
	if (*p == 0) 
		pb->flt->v.ip.proto = num;
	else {
		/* Try /etc/protocols */
		struct protoent *p = getprotobyname(tok);
		if (!p) {
			asprintf(pb->errmsg,
				 "%s: %s",
				 _("Unknown protocol"), tok);
			return 1;
		}
		pb->flt->v.ip.proto = p->p_proto;
	}
	return 0;
}

#define ASCEND_DIR_NONE -1
#define ASCEND_DIR_SRC 0
#define ASCEND_DIR_DST 1

int
_get_direction_type(struct ascend_parse_buf *pb, char *suffix, int lookahead)
{
	char *tok = lookahead ? _lookahead(pb) : _get_token(pb, 1);

	if (!tok && lookahead) 
		return ASCEND_DIR_NONE;
	if (tok && strlen(tok) > 3 && strcmp(tok+3, suffix) == 0) {
		if (strncmp(tok, "dst", 3) == 0)
			return ASCEND_DIR_DST;
		else if (strncmp(tok, "src", 3) == 0)
			return ASCEND_DIR_SRC;
	}
	if (!lookahead)
		asprintf(pb->errmsg,
			 _("Expected {src|dst}port but found `%s'"), tok);
	return ASCEND_DIR_NONE;
}

int
_get_ip(struct ascend_parse_buf *pb)
{
	int dir = _get_direction_type(pb, "ip", 0);
	char *tok;
	UINT4 ip, mask;
	
	if (dir == ASCEND_DIR_NONE)
		return ASCEND_DIR_NONE;
	tok = _get_token(pb, 1);
	if (!tok)
		return ASCEND_DIR_NONE;
	ip = ip_strtoip(tok); /*FIXME: no error checking */

	if (_moreinput(pb) && _lookahead(pb)[0] == '/') {
		char *p;
		
		_get_token(pb, 1);
		tok = _get_token(pb, 1);
		if (!tok)
			return ASCEND_DIR_NONE;
		mask = strtoul(tok, &p, 0);
		if (*p || mask > 32) {
			asprintf(pb->errmsg,
				 "%s: %s",
				 _("Invalid netmask length"), tok);
			return ASCEND_DIR_NONE;
		}
	} else
		mask = 32;

	ip = htonl(ip);
	switch (dir) {
	case ASCEND_DIR_SRC:
		pb->flt->v.ip.src_ip = ip;
		pb->flt->v.ip.src_masklen = mask;
		break;
		
	case ASCEND_DIR_DST:
		pb->flt->v.ip.dst_ip = ip;
		pb->flt->v.ip.dst_masklen = mask;
		break;
	}
	return dir;
}

/* FIXME: if second {src|dst}ip is misspelled, the function returns
   success, supposing it was a portspec */
int
_ascend_parse_ip_clause(struct ascend_parse_buf *pb)
{
	int n;

	if (_get_direction_type(pb, "ip", 1) == ASCEND_DIR_NONE) 
		return 0;
	n = _get_ip(pb);
	if (n == ASCEND_DIR_NONE)
		return 1;
	if (_get_direction_type(pb, "ip", 1) != ASCEND_DIR_NONE) {
		int n1 = _get_ip(pb);
		if (n1 == n) {
			asprintf(pb->errmsg,
				 _("Duplicate IP specification"));
			return 1;
		}
	}
	return 0;
}

int
_get_op(struct ascend_parse_buf *pb)
{
	char *s = _get_token(pb, 1);
	if (!s)
		return ascend_cmp_none;
	switch (s[0]) {
	case '>':
		return ascend_cmp_gt;
	case '<':
		return ascend_cmp_lt;
	case '=':
		return ascend_cmp_eq;
	case '!':
		if (s[1] == '=')
			return ascend_cmp_ne;
	}
	asprintf(pb->errmsg, "%s: %s", _("Invalid operation"), s);
	return ascend_cmp_none;
}

int
_get_port(struct ascend_parse_buf *pb)
{
	int dir = _get_direction_type(pb, "port", 0);
	char *tok;
	char *p;
	int num;
	int op;
	
	if (dir == ASCEND_DIR_NONE)
		return ASCEND_DIR_NONE;

	if ((op = _get_op(pb)) == ascend_cmp_none)
		return ASCEND_DIR_NONE;

	tok = _get_token(pb, 1);
	if (!tok)
		return ASCEND_DIR_NONE;
	
	num = strtoul(tok, &p, 0);
	if (*p == 0) 
		num = htons(num);
	else {
		struct servent *sp;
		struct protoent *pp = getprotobynumber(pb->flt->v.ip.proto);

		if (!pp) {
			/* Shouldn't happen */
			asprintf(pb->errmsg,
				 _("Cannot map back the protocol number"));
			return ASCEND_DIR_NONE;
		}
		sp = getservbyname(tok, pp->p_name);
		if (!sp) {
			asprintf(pb->errmsg,
				 "%s: %s",
				 _("Unknown service"), tok);
			return 1;
		}
		num = sp->s_port;
	}

	switch (dir) {
	case ASCEND_DIR_SRC:
		pb->flt->v.ip.src_port = num;
		pb->flt->v.ip.src_cmp = op;
		break;
		
	case ASCEND_DIR_DST:
		pb->flt->v.ip.dst_port = num;
		pb->flt->v.ip.dst_cmp = op;
		break;
	}

	return dir;
}

int
_ascend_parse_port_clause(struct ascend_parse_buf *pb)
{
	int n = _get_port(pb);

	if (n == ASCEND_DIR_NONE)
		return 1;
	if (_get_direction_type(pb, "port", 1) != ASCEND_DIR_NONE) {
		int n1 = _get_port(pb);
		if (n1 == ASCEND_DIR_NONE)
			return 1;
		if (n1 == n) {
			asprintf(pb->errmsg,
				 _("Duplicate IP specification"));
			return 1;
		}
	}
	return 0;
}

/* IP filter specification is

   "ip" dir action [ "dstip" IP "/" NUM] [ "srcip" IP "/" NUM ]
   	        [ PROTO [ "dstport" cmp PORT ] [ "srcport" cmp PORT ]
                [ "est" ] ]

   where dir    is {"in"|"out"}
         action is {"forward"|"drop"}
	 cmp    is {">"|"<"|"="|"!="}
	 IP     is IP address in dotted-quad
	 NUM    is the decimal number, 0 <= NUM <= 32.
	 PROTO  is either the protocol number or its name from /etc/protocols
	 PORT   is either the port number or its name from /etc/services */

int
_ascend_parse_ip(struct ascend_parse_buf *pb)
{
	if (!_moreinput(pb))
		return 0;
	
	if (_ascend_parse_ip_clause(pb))
		return 1;
	
	if (_moreinput(pb)) {
		if (_get_protocol(pb))
			return 1;
		if (_moreinput(pb)) {
			char *tok;
			if (_ascend_parse_port_clause(pb))
				return 1;
			tok = _get_token(pb, 0);
			if (!tok)
				return 0;
			if (strcmp(tok, "est") == 0)
				pb->flt->v.ip.established = 1;
			else {
				asprintf(pb->errmsg,
					 _("Expected `est' but found `%s'"),
					 tok);
				return 1;
			}
		}
	}
	return 0;
}

/* ************************************************************************* */
/* IPX filter parsing */

/* IPX filter is:

   "ipx" dir action [ "srcipxnet" NETADDR "srcipxnode" NODE
                     [ "srcipxsoc" cmp HEXNUM ]]
                    [ "dstipxnet" NETADDR "dstipxnode" NODE
  		     [ "dstipxsoc" cmp HEXNUM ]] */
int
_ascend_parse_ipx(struct ascend_parse_buf *pb)
{
	asprintf(pb->errmsg, "IPX filters are not yet supported");
	return 1;
}
 
int
_ascend_parse(struct ascend_parse_buf *pb)
{
	memset(pb->flt, 0, sizeof(pb->flt[0]));
	
	if (_get_type(pb)
	    || _get_dir(pb)
	    || _get_action(pb))
		return 1;
	switch (pb->flt->type) {
	case ascend_filter_generic:
		return _ascend_parse_generic(pb);
	case ascend_filter_ip:
		return _ascend_parse_ip(pb);
	case ascend_filter_ipx:
		return _ascend_parse_ipx(pb);
	}
	return 1;
}

/* Parse a single ascend filter specification.
   Return 0 and fill flt[0] if the specification is correct.
   Return !0 and return diagnostics in errp otherwise.
   NOTE: errp is malloced and should be freed using usual free() */
int
_ascend_parse_filter(const char *input, ASCEND_FILTER *flt, char **errp)
{
	struct ascend_parse_buf pb;
	int rc;

	*errp = NULL;
	if (argcv_get(input, "/", &pb.tokc, &pb.tokv)) {
		argcv_free(pb.tokc, pb.tokv);
		asprintf(errp, _("Failed to tokenize"));
		return 1;
	}

	pb.tokn = 0;
	pb.flt = flt;
	pb.errmsg = errp;
	rc = _ascend_parse(&pb);
	argcv_free(pb.tokc, pb.tokv);
	if (rc && !*errp) 
		asprintf(errp, _("Malformed attribute value"));
	return rc;
}

int
ascend_parse_filter(VALUE_PAIR *pair, char **errp)
{
	ASCEND_FILTER flt;
	
	if (_ascend_parse_filter(pair->avp_strvalue, &flt, errp)) 
		return 1;
	efree(pair->avp_strvalue);
	pair->avp_strlength = sizeof(flt);
	pair->avp_strvalue = emalloc(pair->avp_strlength);
	memcpy(pair->avp_strvalue, &flt, sizeof(flt));
	return 0;
}
     
