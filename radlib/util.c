/* This file is part of GNU RADIUS.
   Copyright (C) 2000, 2001 Sergey Poznyakoff
  
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

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#include <radius.h>
#include <checkrad.h>

RADIUS_REQ *
radreq_alloc()
{
	return Alloc_entry(RADIUS_REQ);
}

/* Free a RADIUS_REQ struct.
 */
void 
radreq_free(radreq)
	RADIUS_REQ *radreq;
{
	free_string(radreq->realm);
	avl_free(radreq->server_reply);
	avl_free(radreq->request);
	free_request(radreq);
}


/* Turn printable string (dictionary type DATE) into correct tm struct entries
 */
static char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

int
user_gettime(valstr, tm)
	char *valstr; 
	struct tm *tm;
{
	int	i;

	/* Get the month */
	for (i = 0; i < 12; i++) {
		if (strncasecmp(months[i], valstr, 3) == 0) {
			tm->tm_mon = i;
			break;
		}
	}

	if (i == 12)
		return -1;
	
	valstr += 3;
	while (*valstr && isspace(*valstr))
		valstr++;

	if (!*valstr)
		return -1;
	
	/* Get the Day */
	tm->tm_mday = strtol(valstr, &valstr, 10);

	while (*valstr && isspace(*valstr))
		valstr++;
	if (!*valstr)
		return -1;
	
	/* Now the year */
	tm->tm_year = strtol(valstr, &valstr, 10) - 1900;

	return 0;
}

/* Lock `size' bytes on the file descriptor `fd' starting from `offset'.
 * `whence' determines from where the offset is counted (seek-like)
 */
void
rad_lock(fd, size, offset, whence)
        int fd;
	size_t size;
	off_t offset;
	int whence;
{
	struct flock fl;

	fl.l_type = F_RDLCK;
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	fcntl(fd, F_SETLKW, &fl);
}

/* Unlock `size' bytes on the file descriptor `fd' starting from `offset'.
 * `whence' determines from where the offset is counted (seek-like)
 */
void
rad_unlock(fd, size, offset, whence)
        int fd;
	size_t size;
	off_t offset;
	int whence;
{
	struct flock fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	fcntl(fd, F_SETLKW, &fl);
}

/* Find a struct keyword matching the given string. Return keyword token
 * number if found. Otherwise return default value `def'.
 */
int
xlat_keyword(kw, str, def)
	struct keyword *kw;
	char *str;
	int def;
{
        for ( ; kw->name; kw++) 
		if (strcmp(str, kw->name) == 0)
			return kw->tok;
	return def;
}

/* compose a full pathname from given path and filename
 */
char *
mkfilename(dir, name)
	char *dir;
	char *name;
{
	int len = strlen(dir) + strlen(name);
	char *p = emalloc(len+2);
	sprintf(p, "%s/%s", dir, name);
	return p;
}

/* compose a full pathname from given path, subdirectory and filename
 */
char *
mkfilename3(dir, subdir, name)
	char *dir;
	char *subdir;
	char *name;
{
	int len = strlen(dir) + strlen(subdir) + strlen(name);
	char *p = emalloc(len+3); /* two intermediate slashes and
				   * terminating zero
				   */
	sprintf(p, "%s/%s/%s", dir, subdir, name);
	return p;
}


int
backslash(c)
        int c;
{
	static char transtab[] = "b\bf\fn\nr\rt\t";
	char *p;

	for (p = transtab; *p; p += 2) {
		if (*p == c)
			return p[1];
	}
        return c;
}
	
void
string_copy(d, s, len)
	char *d;
	char *s;
	int  len;
{
	int slen = strlen(s);

	if (slen > len) {
		radlog(L_ERR, _("string too long: %s"), s);
	}
	strncpy(d, s, len);
	d[len] = 0;
}

char *
op_str(op)
        int op;
{
        switch (op) {
        case OPERATOR_EQUAL:         return "=";
        case OPERATOR_NOT_EQUAL:     return "!=";
        case OPERATOR_LESS_THAN:     return "<";
        case OPERATOR_GREATER_THAN:  return ">";
        case OPERATOR_LESS_EQUAL:    return "<=";
        case OPERATOR_GREATER_EQUAL: return ">=";
        }
        return "?";
}

int
pairstr_format(buf, pair)
	char *buf;
	VALUE_PAIR *pair;
{
	int n, ret = 0;
	UINT4		vendor;
	u_char *ptr = (u_char*)pair->strvalue;
	char buf1[64];
	char *bufp = buf;
	u_int left, i, len;
	
	memcpy(&vendor, ptr, 4);
	ptr += 4;
	n = snprintf(buf1, sizeof(buf1), "V%d", (int)ntohl(vendor));
	if (n < 0)
		return -1;
	ret += n;

	if (bufp) {
		memcpy(bufp, buf1, n);
		bufp += n;
	}
	
	left = pair->strlength - 4;
	while (left >= 2) {
		n = snprintf(buf1, sizeof(buf1), ":T%d:L%d:", ptr[0], ptr[1]);
		if (n < 0)
			return n;
		if (bufp) {
			memcpy(bufp, buf1, n);
			bufp += n;
		}
	
		left -= 2;
		ptr += 2;
		i = ptr[1] - 2;

		len = 0;
		do {
			while (i > 0 && left > 0 && isprint(ptr[len])) {
				len++;
				i--;
				left--;
			}
			if (bufp) {
				memcpy(bufp, ptr, len);
				bufp += len;
			}
			ret += len;
			ptr += len;
			if (i > 0 && left > 0) {
				if (bufp) {
					sprintf(bufp, "\\%03o", *ptr);
					bufp += 4;
				}
				ptr++;
				ret += 4;
			}
		} while (i > 0 && left > 0);
	}
	return ret;      
}


char *
format_pair(pair)
	VALUE_PAIR *pair;
{
	static char *buf1;
	char *buf2ptr = NULL, buf2[AUTH_STRING_LEN+1];
	DICT_VALUE *dval;
	
	if (buf1)
		free(buf1);
	buf1 = NULL;

	switch (pair->eval ? TYPE_STRING : pair->type) {
	case TYPE_STRING:
		if (pair->attribute != DA_VENDOR_SPECIFIC) 
			snprintf(buf2, sizeof(buf2), "\"%s\"", pair->strvalue);
		else if (pair->strlength < 6) 
			snprintf(buf2, sizeof(buf2),
				 "[invalid length: %d]", pair->strlength);
		else {
			int len = pairstr_format(NULL, pair);
			buf2ptr = malloc(len+1);
			if (buf2ptr)
				abort();/*FIXME*/
			pairstr_format(buf2ptr, pair);
		}
		break;
					
	case TYPE_INTEGER:
		if (pair->name)
			dval = value_lookup(pair->lvalue, pair->name);
		else
			dval = NULL;
		
		if (!dval)
			snprintf(buf2, sizeof(buf2), "%ld", pair->lvalue);
		else
			snprintf(buf2, sizeof(buf2), "%s", dval->name);
		break;
		
	case TYPE_IPADDR:
		ipaddr2str(buf2, pair->lvalue);
		break;
		
	case TYPE_DATE:
		strftime(buf2, sizeof(buf2), "\"%b %e %Y\"",
			 localtime((time_t *)&pair->lvalue));
		break;
	default:
		strncpy(buf2, "[UNKNOWN DATATYPE]", sizeof(buf2));
	}

	if (pair->name)
		asprintf(&buf1, "%s %s %s",
			 pair->name,
			 op_str(pair->operator),
			 buf2);
	else
		asprintf(&buf1, "%d %s %s",
			 pair->attribute,
			 op_str(pair->operator),
			 buf2ptr ? buf2ptr : buf2);

	if (buf2ptr)
		free(buf2ptr);
	
	return buf1;
}

char *
format_ipaddr(ipaddr)
	UINT4 ipaddr;
{
	static char buf[DOTTED_QUAD_LEN];
	ipaddr2str(buf, ipaddr);
	return buf;
}

void
debug_pair(prefix, pair)
	char *prefix;
	VALUE_PAIR *pair;
{
	fprintf(stdout, "%10.10s: %s\n", prefix, format_pair(pair));
}

