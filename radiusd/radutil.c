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
#define RADIUS_MODULE_RADUTIL_C

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
#include <obstack1.h>

static void attr_to_str(struct obstack *obp, char *pw_digest,
			VALUE_PAIR *request, DICT_ATTR  *attr, char *defval);
static void curtime_to_str(struct obstack *obp, VALUE_PAIR *request, int gmt);
static void attrno_to_str(struct obstack *obp, VALUE_PAIR *request,
			 int attr_no, char *defval);
static DICT_ATTR *parse_dict_attr(char *p, char **endp, char **defval);

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
 * value into obstack.
 * If no attribute found, store the provided default value (defval). If
 * the latter is NULL, store "unknown" for string type and "0" for
 * others.
 */
void
attr_to_str(obp, pw_digest, request, attr, defval)
	struct obstack *obp;
	char *pw_digest;
	VALUE_PAIR *request;
	DICT_ATTR  *attr;
	char *defval;
{
	VALUE_PAIR *pair;
	int len;
	char tmp[AUTH_STRING_LEN];
	
	if (!attr) {
		radlog(L_ERR, "attribute not found");
		return;
	}
	
	if ((pair = avl_find(request, attr->value)) == NULL) {
		if (!defval) {
			if (attr->type == PW_TYPE_STRING)
				defval = "-";
			else
				defval = "-0";
		}
		
		switch (*defval++) {
		case '-':
			len = strlen(defval);
			obstack_grow(obp, defval, len);
			break;
		case '+':
			break;
		case '?':
			if (*defval == 0)
				defval = "Attribute is not present";
			radlog(L_ERR, "%s: %s",
			       attr->name, defval);
			break;
		case '=':
			if (request) {
				pair = install_pair(attr->name,
						    PW_OPERATOR_EQUAL,
						    defval);
				if (pair)
					avl_add_list(&request, pair);
			}
			break;
		default:
			if (defval)
				radlog(L_ERR, "invalid : substitution: %s",
				       defval);
			else
				radlog(L_ERR, "null : substitution");
			break;
		}
		
		if (!pair)
			return;
	} else if (defval && *defval == '+') {
		defval++;
		len = strlen(defval);
		obstack_grow(obp, defval, len);
		return;
	}

	tmp[AUTH_STRING_LEN] = 0;
	switch (attr->type) {
	case PW_TYPE_STRING:
		if (attr->value == DA_PASSWORD && pw_digest) {
			char string[AUTH_PASS_LEN+1];
			int i;
			
			memcpy(string, pair->strvalue, AUTH_PASS_LEN);
			for (i = 0; i < AUTH_PASS_LEN; i++) 
				if ((string[i] ^= pw_digest[i]) == 0)
					break;
			string[i] = '\0';
			obstack_grow(obp, string, i);
		} else {
			/* strvalue might include terminating zero character,
			   so we need to recalculate it */
			int length = strlen(pair->strvalue);
			obstack_grow(obp, pair->strvalue, length);
		}
		break;
	case PW_TYPE_INTEGER:
		snprintf(tmp, sizeof(tmp), "%ld", pair->lvalue);
		len = strlen(tmp);
		obstack_grow(obp, tmp, len);
		break;
	case PW_TYPE_IPADDR:
		ipaddr2str(tmp, pair->lvalue);
		len = strlen(tmp);
		obstack_grow(obp, tmp, len);
		break;
	case PW_TYPE_DATE:
		snprintf(tmp, sizeof(tmp), "%ld", pair->lvalue);
		len = strlen(tmp);
		obstack_grow(obp, tmp, len);
		break;
	default:
		radlog(L_CRIT,
		    _("INTERNAL ERROR (%s:%d): attribute %d has bad type (%d)"),
		    __FILE__, __LINE__,
		    attr->value, attr->type);
		break;
	}
}

void
curtime_to_str(obp, request, gmt)
	struct obstack *obp;
	VALUE_PAIR *request;
	int gmt;
{
	time_t curtime;
	struct tm *tm;
	VALUE_PAIR *pair;
	char tbuf[AUTH_STRING_LEN];
	int len;
	
	curtime = time(NULL);
	if (pair = avl_find(request, DA_ACCT_DELAY_TIME))
		curtime -= pair->lvalue;
	if (gmt)
		tm = gmtime(&curtime);
	else
		tm = localtime(&curtime);
				
	len = strftime(tbuf, AUTH_STRING_LEN, "%Y-%m-%d %H:%M:%S", tm);
	obstack_grow(obp, tbuf, len);
}

/* Find attribute number `attr_no' in pairlist `request' and store it's
 * formatted value into obstack.
 * If no attribute found, use provided default value (see comment to
 * attr_to_str)
 */
void
attrno_to_str(obp, request, attr_no, defval)
	struct obstack *obp;
	VALUE_PAIR *request;
	int attr_no;
	char *defval;
{
	return attr_to_str(obp, NULL, request,
			   attr_number_to_dict(attr_no), defval);
}

static DICT_ATTR *
parse_dict_attr(p, endp, defval)
	char *p;
	char **endp;
	char **defval;
{
	char namebuf[MAX_DICTNAME];
	char *ret;
	
	*defval = NULL;
	if (isdigit(*p)) {
		return attr_number_to_dict(strtol(p, endp, 10));
	}

	if (*p == '{') {
		int len, off;
		
		p++;
		len = strlen(p);
		off = strcspn(p, ":}");

		if (off == len || off >= sizeof namebuf)
			return NULL;

		strncpy(namebuf, p, off);
		namebuf[off] = 0;

		p += off;
		if (*p == ':') {
			int size;
			char *start = p+1;

			for (; *p && *p != '}'; p++) {
				if (*p == '\\' && *++p == 0)
					break;
			}
			if (*p == 0)
				return NULL;

			size = p - start + 1;
			*defval = emalloc(size);
			memcpy(*defval, start, size-1);
			(*defval)[size] = 0;
		}
		*endp = p + 1;
		return attr_name_to_dict(namebuf);
	}
	*endp = p;
	return NULL;
}

char *
radius_xlate(obp, str, req, reply)
	struct obstack *obp;
	char *str;
	RADIUS_REQ *req;
	VALUE_PAIR *reply;
{
	int c;
	char *p;
	DICT_ATTR *da;
	char *defval;

	if (!req) {
		int len = strlen(str);
		obstack_grow(obp, str, len);
		return obstack_finish(obp);
	}
	for (p = str; *p; ) {
		switch (c = *p++) {
		default:
			obstack_1grow(obp, c);
			break;
		case 0:
			goto end;
		case '%':
			switch (c = *p++) {
			case '%':
				obstack_1grow(obp, c);
				break;
			case 'D':
				curtime_to_str(obp, req->request, 0);
				break;
			case 'G':
				curtime_to_str(obp, req->request, 1);
				break;
			case 'f': /* Framed IP address */
				attrno_to_str(obp, reply,
					      DA_FRAMED_IP_ADDRESS, NULL);
				break;
			case 'n': /* NAS IP address */
				attrno_to_str(obp, req->request,
					      DA_NAS_IP_ADDRESS, NULL);
				break;
			case 't': /* MTU */
				attrno_to_str(obp, reply,
					      DA_FRAMED_MTU, NULL);
				break;
			case 'p': /* Port number */
				attrno_to_str(obp, req->request,
					      DA_NAS_PORT_ID, NULL);
				break;
			case 'u': /* User name */
				attrno_to_str(obp, req->request,
					      DA_USER_NAME, NULL);
				break;
			case 'c': /* Callback-Number */
				attrno_to_str(obp, reply,
					      DA_CALLBACK_NUMBER, NULL);
				break;
			case 'i': /* Calling station ID */
				attrno_to_str(obp, req->request,
					      DA_CALLING_STATION_ID, NULL);
				break;
			case 'a': /* Protocol: SLIP/PPP */
				attrno_to_str(obp, reply,
					      DA_FRAMED_PROTOCOL, NULL);
				break;
			case 's': /* Speed */
				attrno_to_str(obp, req->request,
					      DA_CONNECT_INFO, NULL);
				break;
			case 'C':
				/* Check pair */
				da = parse_dict_attr(p, &p, &defval);
				attr_to_str(obp, req->digest, req->request,
					    da, defval);
				efree(defval);
				break;
			case 'R':
				/* Reply pair */
				da = parse_dict_attr(p, &p, &defval);
				attr_to_str(obp, NULL, req->request,
					    da, defval);
				break;
			default:					
				obstack_1grow(obp, '%');
				obstack_1grow(obp, c);
				break;
			}
			break;
			
		case '\\':
			switch (c = *p++) {
			case 'a':
				obstack_1grow(obp, '\a');
				break;
			case 'b':
				obstack_1grow(obp, '\b');
				break;
			case 'f':
				obstack_1grow(obp, '\f');
				break;
			case 'e':
				obstack_1grow(obp, '\033');
				break;
			case 'n':
				obstack_1grow(obp, '\n');
				break;
			case 'r':
				obstack_1grow(obp, '\r');
				break;
			case 't':
				obstack_1grow(obp, '\t');
				break;
			case 0:
				goto end;
			default:
				obstack_1grow(obp, '%');
				obstack_1grow(obp, c);
				break;
			}
		}
	}
	
end:
	obstack_1grow(obp, 0);
	return obstack_finish(obp);
}





