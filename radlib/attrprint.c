/*
 *
 *	RADIUS
 *	Remote Authentication Dial In User Service
 *
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.   
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 */

static char rcsid[] = 
"$Id$";

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>

#include	<radiusd.h>

char *opstr[] = {
	"=",
	"!=",
	"<",
	">",
	"<=",
	">=",
};


/*
 *	Write a whole list of A/V pairs.
 */
void 
fprint_attr_list(fd, pair)
	FILE *fd;
	VALUE_PAIR *pair;
{
	while (pair) {
		fprintf(fd, "    ");
		fprint_attr_val(fd, pair);
		fprintf(fd, "\n");
		pair = pair->next;
	}
}


/*
 *	Write a printable version of the attribute-value
 *	pair to the supplied File.
 */
void 
fprint_attr_val(fd, pair)
	FILE *fd;
	VALUE_PAIR *pair;
{
	DICT_VALUE	*dict_valget();
	DICT_VALUE	*dval;
	char		buffer[32];
	u_char		*ptr;
	UINT4		vendor;
	int		i, left;

	if (!pair->name)
		return;

	insist(pair->operator >= 0 && pair->operator < PW_NUM_OPERATORS);

	switch (pair->type) {

	case PW_TYPE_STRING:
		fprintf(fd, "%s %s \"", pair->name, opstr[pair->operator]);
		ptr = (u_char *)pair->strvalue;
		if (pair->attribute != DA_VENDOR_SPECIFIC) {
			left = pair->strlength;
			while(left-- > 0) {
				/*
				 *	Ugh! Ascend gear sends "foo"
				 *	as "foo\0", length 4.
				 *	Suppress trailing zeros.
				 */
				if (left == 0 && *ptr == 0)
					break;
				if(!(isprint(*ptr)))
					fprintf(fd, "\\%03o", *ptr);
				else
					fputc(*ptr, fd);
				ptr++;
			}
			fputc('"', fd);
			break;
		}
		/*
		 *	Special format, print out as much
		 *	info as we can.
		 */
		if (pair->strlength < 6) {
			fprintf(fd, _("(invalid length: %d)\""), pair->strlength);
			break;
		}
		memcpy(&vendor, ptr, 4);
		ptr += 4;
		fprintf(fd, "V%d", (int)ntohl(vendor));
		left = pair->strlength - 4;
		while (left >= 2) {
			fprintf(fd, ":T%d:L%d:", ptr[0], ptr[1]);
			left -= 2;
			ptr += 2;
			i = ptr[1] - 2;
			while (i > 0 && left > 0) {
				if(!(isprint(*ptr)))
					fprintf(fd, "\\%03o", *ptr);
				else
					fputc(*ptr, fd);
				ptr++;
				i--;
				left--;
			}
		}
		fputc('"', fd);
		break;

	case PW_TYPE_INTEGER:
		dval = dict_valget(pair->lvalue, pair->name);
		if(dval != (DICT_VALUE *)NULL) {
			fprintf(fd, "%s %s %s", pair->name, opstr[pair->operator], 
				dval->name);
		}
		else {
			fprintf(fd, "%s %s %ld", pair->name, 
				opstr[pair->operator], (long)pair->lvalue);
		}
		break;

	case PW_TYPE_IPADDR:
		ipaddr2str(buffer, pair->lvalue);
		fprintf(fd, "%s %s %s", pair->name, opstr[pair->operator], buffer);
		break;

	case PW_TYPE_DATE:
		strftime(buffer, sizeof(buffer), "%b %e %Y",
					localtime((time_t *)&pair->lvalue));
		fprintf(fd, "%s %s \"%s\"", pair->name, opstr[pair->operator], 
			buffer);
		break;

	default:
		fprintf(fd, _("Unknown type %d"), pair->type);
		break;
	}
}
