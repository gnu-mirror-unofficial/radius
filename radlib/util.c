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

/* Convert second character of a backslash sequence to its ASCII
   value: */
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
	
	if (slen > len) 
		radlog(L_ERR, _("string too long: %s"), s);
	strncpy(d, s, len);
	d[len] = 0;
}

char *
op_to_str(op)
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
str_to_op(str)
	char *str;
{
	int op = NUM_OPERATORS;
	switch (*str++) {
	case '=':
		op = OPERATOR_EQUAL;
		break;
	case '!':
		if (*str++ == '=')
			op = OPERATOR_NOT_EQUAL;
		break;
	case '<':
		if (*str == 0)
			op = OPERATOR_LESS_THAN;
		else if (*str++ == '=')
			op = OPERATOR_LESS_EQUAL;
		break;
	case '>':
		if (*str == 0)
			op = OPERATOR_GREATER_THAN;
		else if (*str++ == '=')
			op = OPERATOR_GREATER_EQUAL;
		break;
        }
	if (*str)
		op = NUM_OPERATORS;
	return op;
}

static int flush_seg(char **bufp, char *seg, char *ptr, int runlen);

int
flush_seg(bufp, seg, ptr, runlen)
	char **bufp;
	char *seg;
	char *ptr;
	int runlen;
{
	int outbytes = 0;
	char *buf = *bufp;
	
	if (ptr - seg >= runlen) {
		outbytes += ptr - seg;
		if (buf)
			while (seg < ptr)
				*buf++ = *seg++;
	} else {
		outbytes += 4*(ptr - seg);
		if (buf)
			while (seg < ptr) {
				sprintf(buf, "\\%03o", *seg);
				seg++;
				buf += 4;
			}
	}
	*bufp = buf;
	return outbytes;
}

/* Print LEN characters from STR to buffer BUF. If a sequence of RUNLEN
   or more printable characters is encountered, it is printed as is,
   otherwise, each character is printed as a three-digit octal number,
   preceeded by a backslash (\%03o).
   Return number of characters, _output_ to BUF. If BUF is NULL, no
   printing is done, but the number of characters that would be output
   (not counting null terminator) is returned. */

int
format_string_visual(buf, runlen, str, len)
	char *buf;
	int runlen;
	char *str;
	int len;
{
	char *seg, *ptr;
	int outbytes = 0;

	seg = NULL;
	ptr = str;
	while (len) {
		if (isprint(*ptr)) {
			if (!seg)
				seg = ptr;
		} else {
			if (seg) {
				outbytes += flush_seg(&buf, seg, ptr, runlen);
				seg = NULL;
			}
			if (buf) {
				sprintf(buf, "\\%03o", *ptr);
				buf += 4;
			}
			outbytes += 4;
		}
		len--;
		ptr++;
	}
	/* Make last segment printable no matter how many chars it contains */
	if (seg) {
		outbytes += ptr - seg;
		if (buf)
			while (seg < ptr) 
				*buf++ = *seg++;
	}
	if (buf)
		*buf++ = 0;
	return outbytes;
}

int
format_vendor_pair(buf, pair)
	char *buf;
	VALUE_PAIR *pair;
{
	int n;
	UINT4 vendor;
	u_char *ptr = (u_char*)pair->strvalue;
	char buf1[64];
	char *bufp = buf;
	
	memcpy(&vendor, ptr, 4);
	ptr += 4;
	n = snprintf(buf1, sizeof(buf1), "V%d", (int)ntohl(vendor));
	if (n < 0)
		return -1;

	if (bufp) {
		memcpy(bufp, buf1, n);
		bufp += n;
	}
	
	return n + format_string_visual(bufp, 4, ptr, pair->strlength - 4);
}
		
char *
format_pair(pair, savep)
	VALUE_PAIR *pair;
	char **savep;
{
	char *buf1 = NULL;
	char *buf2ptr = NULL;
	char buf2[4*AUTH_STRING_LEN+1]; /* Enough to hold longest possible
					   string value all converted to
					   octal */
	DICT_VALUE *dval;
	struct tm tm;
	
	*savep = NULL;

	switch (pair->eval ? TYPE_STRING : pair->type) {
	case TYPE_STRING:
		if (pair->attribute != DA_VENDOR_SPECIFIC) {
			int len = strlen (pair->strvalue);
			if (len != pair->strlength-1)
				len = pair->strlength;
			format_string_visual(buf2, 4,
					     pair->strvalue, len);
		} else if (pair->strlength < 6) 
			snprintf(buf2, sizeof(buf2),
				 "[invalid length: %d]", pair->strlength);
		else {
			int len = format_vendor_pair(NULL, pair);
			buf2ptr = malloc(len+1);
			if (!buf2ptr) {
				radlog(L_ERR,
				       "%s:%d: can't alloc %d bytes",
				       __FILE__, __LINE__);
				buf2[0] = 0;
			} else
				format_vendor_pair(buf2ptr, pair);
		}
		break;
					
	case TYPE_INTEGER:
		if (pair->name)
			dval = value_lookup(pair->lvalue, pair->name);
		else
			dval = NULL;
		
		if (!dval)
			snprintf(buf2, sizeof(buf2), "%lu", pair->lvalue);
		else
			snprintf(buf2, sizeof(buf2), "%s", dval->name);
		break;
		
	case TYPE_IPADDR:
		ipaddr2str(buf2, pair->lvalue);
		break;
		
	case TYPE_DATE:
		strftime(buf2, sizeof(buf2), "\"%b %e %Y\"",
			 localtime_r((time_t *)&pair->lvalue, &tm));
		break;
	default:
		strncpy(buf2, "[UNKNOWN DATATYPE]", sizeof(buf2));
	}

	if (pair->name)
		asprintf(&buf1, "%s %s %s",
			 pair->name,
			 op_to_str(pair->operator),
			 buf2ptr ? buf2ptr : buf2);
	else
		asprintf(&buf1, "%d %s %s",
			 pair->attribute,
			 op_to_str(pair->operator),
			 buf2ptr ? buf2ptr : buf2);

	if (buf2ptr)
		free(buf2ptr);
	
	*savep = buf1;
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



