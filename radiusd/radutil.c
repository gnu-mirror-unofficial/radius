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
#define RADIUS_MODULE 15

#ifndef lint
static char rcsid[] =
"@(#) $Id$"; 
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <sysdep.h>
#include <radiusd.h>

/*
 *	Replace %<whatever> in a string.
 *
 *      %Cnum          attribute number `num' from check pairs
 *      %C{attr-name}  attribute `attr-name' from check pairs
 *      %Rnum          attribute number `num' from reply pairs
 *      %R{attr-name}  attribute `attr-name' from reply pairs
 *      %D             current date/time (localtime)
 *      %G             current date/time (GMT)
 *      Shortcuts:
 *	%p             Port number
 *	%n             NAS IP address
 *	%f             Framed IP address
 *	%u             User name
 *	%c             Callback-Number
 *      %i             Calling-Station-Id
 *	%t             MTU
 *	%a             Protocol (SLIP/PPP)
 *	%s             Speed (DA_CONNECT_INFO)
 *
 */

/* Find attribute `attr' in pairlist `request' and store it's formatted
 * value into buffer `buf'.
 * If no attribute found, store the word "unknown" for string type and 0 for
 * others.
 * Return length of the resulting buffer not counting terminating zero.
 * NOTE: buffer should be AUTH_STRING_LEN+1 bytes long.
 */
static int
attr_to_str(buf, request, attr)
	char *buf;
	VALUE_PAIR *request;
	DICT_ATTR  *attr;
{
	VALUE_PAIR *pair;
	char tmp[AUTH_STRING_LEN+1];
	
	if (!attr) {
		strcpy(buf, _("unknown"));
		return strlen(buf);
	}
	
	if ((pair = pairfind(request, attr->value)) == NULL) {
		debug(1, ("attribute %d not found in packet",
		    	attr->value));
		if (attr->type == PW_TYPE_STRING)
			strcpy(buf, _("unknown"));
		else
			strcpy(buf, "0");
		return strlen(buf);
	}

	tmp[AUTH_STRING_LEN] = 0;
	switch (attr->type) {
	case PW_TYPE_STRING:
		strncpy(tmp, pair->strvalue, AUTH_STRING_LEN);
		break;
	case PW_TYPE_INTEGER:
		sprintf(tmp, "%ld", pair->lvalue);
		break;
	case PW_TYPE_IPADDR:
		ipaddr2str(tmp, pair->lvalue);
		break;
	case PW_TYPE_DATE:
		sprintf(tmp, "%ld", pair->lvalue);
		break;
	default:
		radlog(L_CRIT,
		    _("INTERNAL ERROR (%s:%d): attribute %d has bad type (%d)"),
		    __FILE__, __LINE__,
		    attr->value, attr->type);
		strcpy(tmp, _("unknown"));
		break;
	}
	strcpy(buf, tmp);
	return strlen(buf);
}

int
curtime_to_str(tbuf, request, gmt)
	char *tbuf;
	VALUE_PAIR *request;
	int gmt;
{
	time_t curtime;
	struct tm *tm;
	VALUE_PAIR *pair;
	
	
	curtime = time(NULL);
	if (pair = pairfind(request, DA_ACCT_DELAY_TIME))
		curtime -= pair->lvalue;
	if (gmt)
		tm = gmtime(&curtime);
	else
		tm = localtime(&curtime);
				
	strftime(tbuf, AUTH_STRING_LEN, "%Y-%m-%d %H:%M:%S", tm);
	return strlen(tbuf);
}

/* Find attribute number `attr_no' in pairlist `request' and store it's
 * formatted value into buffer `buf'.
 * If no attribute found, store the word "unknown".
 * Return length of the resulting buffer not counting terminating zero.
 * NOTE: buffer should be AUTH_STRING_LEN+1 bytes long.
 */
static int
attrno_to_str(buf, request, attr_no)
	char *buf;
	VALUE_PAIR *request;
	int attr_no;
{
	return attr_to_str(buf, request, dict_attrget(attr_no));
}

static DICT_ATTR *
parse_dict_attr(p, endp)
	char *p;
	char **endp;
{
	char namebuf[MAX_DICTNAME];
	
	if (isdigit(*p)) {
		return dict_attrget(strtol(p, endp, 10));
	}
	if (*p == '{') {
		int len;
		char *stop = strchr(p, '}');
		if (stop == NULL) 
			return NULL;
		*endp = stop + 1;
		len = stop-p-1;
		if (len >= sizeof namebuf)
			return NULL;
		strncpy(namebuf, p+1, len);
		namebuf[len] = 0;
		return dict_attrfind(namebuf);
	}
	*endp = p;
	return NULL;
}

char *
radius_xlate(buf, bufsize, str, request, reply)
	char *buf;
	int bufsize;
	char *str;
	VALUE_PAIR *request;
	VALUE_PAIR *reply;
{
	char tbuf[AUTH_STRING_LEN+1];
	int i = 0, c, len;
	char *p;

#define CHECK(n) if (i + (n) >= bufsize) goto overflow;
	
	for (p = str; *p; ) {
		if (i >= bufsize)
			goto overflow;
		switch (c = *p++) {
		default:
			buf[i++] = c;
			break;
		case 0:
			goto end;
		case '%':
			len = 0;
			switch (c = *p++) {
			case '%':
				CHECK(1);
				buf[i++] = c;
				break;
			case 'D':
				len = curtime_to_str(tbuf, request, 0);
				break;
			case 'G':
				len = curtime_to_str(tbuf, request, 1);
				break;
			case 'f': /* Framed IP address */
				len = attrno_to_str(tbuf, reply,
						    DA_FRAMED_IP_ADDRESS);
				break;
			case 'n': /* NAS IP address */
				len = attrno_to_str(tbuf, request,
						    DA_NAS_IP_ADDRESS);
				break;
			case 't': /* MTU */
				len = attrno_to_str(tbuf, reply,
						    DA_FRAMED_MTU);
				break;
			case 'p': /* Port number */
				len = attrno_to_str(tbuf, request,
						    DA_NAS_PORT_ID);
				break;
			case 'u': /* User name */
				len = attrno_to_str(tbuf, request,
						    DA_USER_NAME);
				break;
			case 'c': /* Callback-Number */
				len = attrno_to_str(tbuf, reply,
						    DA_CALLBACK_NUMBER);
				break;
			case 'i': /* Calling station ID */
				len = attrno_to_str(tbuf, request,
						    DA_CALLING_STATION_ID);
				break;
			case 'a': /* Protocol: SLIP/PPP */
				len = attrno_to_str(tbuf, reply,
						    DA_FRAMED_PROTOCOL);
				break;
			case 's': /* Speed */
				len = attrno_to_str(tbuf, request,
						    DA_CONNECT_INFO);
				break;
			case 'C':
				/* Check pair */
				len = attr_to_str(tbuf, request,
						  parse_dict_attr(p, &p));
				break;
			case 'R':
				/* Reply pair */
				len = attr_to_str(tbuf, request,
						  parse_dict_attr(p, &p));
				break;
			default:					
				CHECK(2);
				buf[i++] = '%';
				buf[i++] = c;
				break;
			}
			if (len > 0) {
				CHECK(len);
				strcpy(buf + i, tbuf);
				i += len;
			}
			break;
			
		case '\\':
			switch (c = *p++) {
			case 'a':
				buf[i++] = '\a';
				break;
			case 'b':
				buf[i++] = '\b';
				break;
			case 'f':
				buf[i++] = '\f';
				break;
			case 'e':
				buf[i++] = '\033';
				break;
			case 'n':
				buf[i++] = '\n';
				break;
			case 'r':
				buf[i++] = '\r';
				break;
			case 't':
				buf[i++] = '\t';
				break;
			case 0:
				goto end;
			default:
				CHECK(2);
				buf[i++] = '\\';
				buf[i++] = c;
				break;
			}
		}
	}
	
end:
	buf[i] = 0;
	return buf;

overflow:
	radlog(L_ERR, _("radius_xlat: result truncated while expanding `%s'"),
	    str);
	buf[i] = 0;
	return buf;
}



void
alloc_buffer(buf, newsize)
	BUFFER *buf;
	int newsize;
{
	if (!buf->ptr) {
		if (newsize)
			buf->size = newsize;
		buf->ptr = emalloc(buf->size);
	} else if (newsize && newsize != buf->size) {
		void *p;

		p = xmalloc(newsize);
		if (!p) {
			radlog(L_ERR,
			       _("can't reallocate buffer from %d to %d bytes"),
			       buf->size, newsize);
			return;
		} 
		efree(buf->ptr);
		buf->ptr = p;
		buf->size = newsize;
	}
}



