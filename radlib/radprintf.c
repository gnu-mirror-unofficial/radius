/* This file is part of GNU RADIUS.
 * Copyright (C) 2001, Sergey Poznyakoff
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

/* This module defines (v)printf-like functions with some extensions.
 * The size of output buffer is checked.
 * The format specifications are:
 *
 *  %[-+ 0#]*(\*|[0-9]+)?(\.\*|[0-9]+)?[hl]?[diouxXeEfgcsAI]
 *  %%
 *
 * Additional format sequences are:
 *  %A       Print next argument as a radius Attribute/Value pair
 *  %I       Print next argument as an IP address in dotted-quad form.
 *           The address must be in hostorder.
 *
 * FIXME: FLOATING POINT FORMATS ARE NOT SUPPORTED. Upon encountering
 *        %[eEfg] spec, functions read next argument as double and
 *        simply output the format spec as is.
 * FIXME2: The return value is not consistent?
 */

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <varargs.h>
#include <limits.h>

#include <radiusd.h>

#ifdef STANDALONE
# define DEBUG1
#endif

/* ************************************************************************* */
/* IO buffer functions */

#define IO_STRING 0
#define IO_FILE   1
typedef struct {
	int    type;    /* either IO_STRING or IO_FILE */
	char   *io_base;
	int    io_size;
	int    io_level;
	FILE   *io_stream;
} IO_BUF;

#ifdef DEBUG
void IO_PUT(IO_BUF *buf, char *src, int len);
#endif
void io_flush(IO_BUF *buf);
int io_checksize(IO_BUF *buf, int len);
void io_put(IO_BUF *buf, char *src, int len);

#ifdef DEBUG
void
IO_PUT(b, s, l) 
	IO_BUF *b;
	char *s;
	int l;
{
	if ((b)->io_size < l) 
		io_put(b,s,l); 
	else { 
		if ((b)->io_level + l >= (b)->io_size) 
			io_flush(b);
		if ((b)->io_level + l < (b)->io_size) {
			memcpy((b)->io_base + (b)->io_level, s, l); 
			(b)->io_level += l;
		}
	}
}
#else
#define IO_PUT(b, s, l) \
  do {\
	if ((b)->io_size < l) \
		io_put(b,s,l); \
	else { \
		if ((b)->io_level + l >= (b)->io_size) \
			io_flush(b);\
		if ((b)->io_level + l < (b)->io_size) {\
			memcpy((b)->io_base + (b)->io_level, s, l); \
			(b)->io_level += l;\
		}\
	}\
   } while(0)		 
#endif

int
io_checksize(buf, len)
	IO_BUF *buf;
	int len;
{
	if (buf->type == IO_FILE)
		return 0;
	return buf->io_level + len >= buf->io_size;
}

void
io_put(buf, src, len)
        IO_BUF *buf;
	char *src;
	int len;
{
	int outsize = buf->io_size;
	while (len > 0) {
		if (len > buf->io_size)
			outsize = buf->io_size;
		else
			outsize = len;
		IO_PUT(buf, src, outsize);
		len -= outsize;
	}
}

void
io_flush(buf)
	IO_BUF *buf;
{
	if (buf->type == IO_FILE) {
		fwrite(buf->io_base, buf->io_level, 1, buf->io_stream);
		buf->io_level = 0;
	} else
		buf->io_base[buf->io_level] = 0;
}

/* ************************************************************************* */
/* conversion routines */

#define	to_digit(c)	((c) - '0')
#define is_digit(c)	((unsigned)to_digit(c) <= 9)
#define	to_char(n)	(char)((n) + '0')

char *
icvt(val, cp, base, octzero, xdigs)
	register u_long val;
	char *cp;
	int base, octzero;
	char *xdigs;
{
	register long sval;

	switch (base) {
	case 10:
		if (val < 10) {
			*--cp = to_char(val);
			break;
		}

		if (val > LONG_MAX) {
			*--cp = to_char(val % 10);
			val /= 10;
		}
		sval = val;
		/*
		 * convert rest of digits
		 */
		do {
			*--cp = to_char(sval % 10);
			sval /= 10;
		} while (sval);
		break;

	case 8:
		do {
		        *--cp = to_char(val & 7);
			val >>= 3;
	        } while (val);
		if (octzero && *cp != '0')
			*--cp = '0';
		break;
		
	case 16:
		do {
		        *--cp = xdigs[val & 15];
			val >>= 4;
	        } while (val);
		break;
	}
	return cp;
}

char *
op_str(op)
	int op;
{
	switch (op) {
	case PW_OPERATOR_EQUAL:         return "=";
	case PW_OPERATOR_NOT_EQUAL:     return "!=";
	case PW_OPERATOR_LESS_THAN:     return "<";
	case PW_OPERATOR_GREATER_THAN:  return ">";
	case PW_OPERATOR_LESS_EQUAL:    return "<=";
	case PW_OPERATOR_GREATER_EQUAL: return ">=";
	}
	return "?";
}

int
pairstr_format(f, pair)
	IO_BUF *f;
	VALUE_PAIR *pair;
{
	u_char		*ptr;
	UINT4		vendor;
	int		i, left, len;
	int             ret, n;
	
	if (pair->attribute != DA_VENDOR_SPECIFIC) 
		return radprintv(f, "\"%s\"", pair->strvalue);

	if (pair->strlength < 6) 
		return radprintv(f, "[invalid length: %d]", pair->strlength);

	ret = 0;
	
	ptr = (u_char *)pair->strvalue;
	memcpy(&vendor, ptr, 4);
	ptr += 4;
	if ((n = radprintv(f, "V%d", (int)ntohl(vendor))) == -1)
		return n;
	ret += n;
	
	left = pair->strlength - 4;
	while (left >= 2) {
		if ((n = radprintv(f, ":T%d:L%d:", ptr[0], ptr[1])) == -1)
			return n;
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
			IO_PUT(f, (char*)ptr, len);
			ret += len;
			ptr += len;
			if (i > 0 && left > 0) {
				if ((n = radprintv(f, "\\%03o", *ptr++)) == -1)
					return n;
				ret += n;
			}
		} while (i > 0 && left > 0);
	}
	return n;      
}

/* ************************************************************************* */
/*
 * Specifications recognized:
 *
 *  %[-+ 0#]*(\*|[0-9]+)?(\.\*|[0-9]+)?[hl]?[diouxXeEfgcsAI]
 *  %%
 *
 * States:
 *   <INI>%
 *   <FLG>[-+ 0#]?
 *   <WID>(\*|[0-9]+)?
 *   <PRC>(\.\*|[0-9]+)?
 *   <MOD>[hl]?
 *   <FIN>[AdiouxXeEfgcs]
 */

enum {
	INI,
	FLG,
	WID,
	PRC,
	MOD,
	FIN
};

#define F_NONE 0
#define F_LEFT   001
#define F_RIGHT  002
#define F_SHORT  004
#define F_LONG   010
#define F_ALT    020
#define F_0PAD   040


#define BUF 68 

/*PRINTFLIKE2*/
int
radprintv(f, fmt, va_alist)
	IO_BUF *f;
	char   *fmt;
	va_dcl
{
	va_list ap;
	int rc;
	
	va_start(ap);
	rc = radprint(f, fmt, ap);
	va_end(ap);
	return rc;
}

int
radprint(f, fmt, ap)
	IO_BUF *f;
	char   *fmt;
	va_list ap;
{
	int ret, n;          
	int state;
	int width, prec, flags;
	char *xdigs;
	char *cp;
	u_long ulval;
	char sign;
	int prsize, realsz, size;
	int dprec;
	char ch, c;
	char buf[BUF];	       
	int base;
	VALUE_PAIR *pair;
	DICT_VALUE *dval;

	/*
	 * Some useful macros
	 */
	/* Switch to new state */
        #define newstate(s) state=s
	/* Return next signed argument */
	#define sarg() \
	((flags&F_LONG) ? va_arg(ap,long) : \
	       ((flags&F_SHORT) ? (long)(short)va_arg(ap,int) : \
		(long)va_arg(ap,int)))
	/* Return next unsigned argument */
	#define uarg() \
	((flags&F_LONG) ? va_arg(ap,u_long) : \
	       ((flags&F_SHORT) ? (u_long)(u_short)va_arg(ap,int) : \
		(u_long)va_arg(ap,u_int)))

	/* Convert width or prec and place result in n */	
	#define NUM(n) \
	if (*fmt == '*') {\
		fmt++;\
		n = va_arg(ap,int);\
	} else for (; is_digit(*fmt); fmt++) {\
		n = 10*n+to_digit(*fmt);\
	}

	/* Output l bytes from s */
	#define PUT(s,l) do { IO_PUT(f,s,l); ret += l; } while (0)
        /* Flush output stream */
        #define FLUSH() io_flush(f)
	/* Check if output stream is able to accept l bytes more */
        #define CHECKSIZE(l) io_checksize(f,l)
	/* Pad output with sz copies of char c. Do nothing if sz <= 0 */
	#define PAD(sz,c) \
	if (sz>0) do { int len = sz; ret += len; while (len--) IO_PUT(f,&c,1); } while (0)

	/*
	 * Begin
	 */
	state = INI;
	ret = 0;
	while (*fmt) {
		switch (state) {
		case INI: 
			if (*fmt == '%') {
				flags = F_NONE;
				width = 0;
				prec = -1;
				dprec = 0;
				sign = 0;
				newstate(FLG);
			} else 
				PUT(fmt, 1);
			fmt++;
			break;
		case FLG: /*  <FLG>[-+ 0]? */
			switch (*fmt) {
			case '-':
				fmt++;
				flags |= F_LEFT;
				break;
			case '+':
				fmt++;
				flags |= F_RIGHT;
				break;
			case ' ':
				if (!sign)
					sign = ' ';
				fmt++;
				break;
			case '0':
				fmt++;
				flags |= F_0PAD;
				break;
			case '#':
				fmt++;
				flags |= F_ALT;
				break;
			case '%':
				PUT(fmt, 1);
				fmt++;
				newstate(INI);
				break;
			default:
				newstate(WID);
			}
			break;

		case WID: /* <WID>(\*|[0-9]+)? */
			NUM(width);
			newstate(PRC);
			break;
			
		case PRC: /* <PRC>(\.\*|[0-9]+)? */
			if (*fmt == '.') {
				++fmt;
				prec = 0;
				NUM(prec);
			}
			newstate(MOD);
			break;
				
		case MOD: /* <MOD>[hl]? */
			switch (*fmt) {
			case 'h':
				fmt++;
				flags |= F_SHORT;
				break;
			case 'l':
				fmt++;
				flags |= F_LONG;
				break;
			}
			newstate(FIN);
			break;
			
				
		case FIN: /* <FIN>[AdiouxXeEfgcs] */
			switch (ch = *fmt) {
			case 'e':
			case 'E':
			case 'f':
			case 'g':
				va_arg(ap,double);
				PUT(fmt-1,2);
				fmt++;
				newstate(INI);
				continue;
				
			case 's':
				if ((cp = va_arg(ap,char*)) == NULL)
					cp = "(null)";
			string:	if (prec >= 0) {
					char *p;

					size = 0;
					for (p=cp; *p && size < prec; p++)
						size++;
				} else
					size = strlen(cp);
				sign = 0;
				break;

			case 'c':
				ch = va_arg(ap,int);
				cp = &ch;
				size = 1;
				break;

				/* Integer conversions */
			case 'd':
			case 'i':
				if ((long)(ulval = sarg()) < 0) {
					sign = '-';
					ulval = -ulval;
				}
				base = 10;
				if (flags & F_RIGHT) {
					if (sign == 0) {
						if (ulval == 0)
							sign = ' ';
						else
							sign = '+';
					}
				}
				goto number;
			case 'p':
				cp = va_arg(ap, char*);
				if (cp == NULL) {	
					cp = "(nil)";
					goto string;
				} else {
					ulval = (u_long) cp;
					size = 8;
					flags = F_ALT;
					ch = 'x';
					xdigs = "0123456789abcdef";
					base = 16;
					goto unsign;
				}
				break;
				
			case 'o':
				ulval = sarg();
				base = 8;
				goto number;
			case 'u':
				ulval = uarg();
				base = 10;
				goto unsign;
			case 'x':
			        xdigs = "0123456789abcdef";
				goto hex;
			case 'X':
				xdigs = "0123456789ABCDEF";
			  hex:
				ulval = uarg();
				base = 16;
			  unsign:
				sign = 0;
		number:
				if (prec >= 0)
					flags &= ~F_0PAD;
				cp = buf + BUF;
				if (ulval != 0 || prec != 0) 
					cp = icvt(ulval, cp, base,
						  flags & F_ALT, xdigs);
				if (*fmt == 'o')
					flags &= ~F_ALT;
				size = buf + BUF - cp;
				break;

				/* Additions to standard format specifiers */
			  ipaddr:
			case 'I': /* IP address */
				ipaddr2str(buf, uarg());
				cp = buf;
				goto string;

			  avpair:
			case 'A': /* Attribute/Value pair */
				pair = va_arg(ap, VALUE_PAIR*);
				if (pair->name)
					n = radprintv(f, "%s %s ",
						      pair->name,
						      op_str(pair->operator));
				else
					n = radprintv(f, "%d %s ",
						      pair->attribute,
						      op_str(pair->operator));
				if (n == -1) {
					ret = n;
					goto error;
				}
				ret += n;
				
				switch (pair->eval ? PW_TYPE_STRING :
					pair->type) {
				case PW_TYPE_STRING:
					n = pairstr_format(f, pair);
					break;
					
				case PW_TYPE_INTEGER:
					if (pair->name)
						dval = value_lookup(
							pair->lvalue,
							pair->name);
					else
						dval = NULL;
					
					if (!dval)
						n = radprintv(f, "%ld",
							      pair->lvalue);
					else
						n = radprintv(f, "%s",
							      dval->name);
					break;
				case PW_TYPE_IPADDR:
					n = radprintv(f, "%I",
						      pair->lvalue);
					break;
				case PW_TYPE_DATE:
					strftime(buf, sizeof(buf),
						 "%b %e %Y",
						 localtime(
					       	 (time_t *)&pair->lvalue));
					n = radprintv(f, "\"%s\"", buf);
					break;
				default:
					n = radprintv(f, "[UNKNOWN DATATYPE]");
				}
				
				if (n == -1) {
					ret = n;
					goto error;
				}
				ret += n;

				/*FALLTHRU*/
				
			default:
				fmt++;
				newstate(INI);
				continue;
			}

			/*
			 * We have just processed a *valid* format spec.
			 * Add any necessary alignment.
			 */
			realsz = dprec > size ? dprec : size;
			if (sign)
				realsz++;
			else if (flags & F_ALT)
				realsz += 2;

			prsize = width > realsz ? width : realsz;

			if (CHECKSIZE(prsize)) {
				ret = -1;
				goto error;
			}
			if ((flags & (F_LEFT|F_0PAD)) == 0) {
				c = ' ';
				PAD(width - realsz, c);
			}
			
			if (sign)
				PUT(&sign, 1);
			else if (flags & F_ALT) {
                                /* add 0x */
				char pref[2];
				pref[0] = '0';
				pref[1] = ch;
				PUT(pref, 2);
			}

			if ((flags & (F_LEFT|F_0PAD)) == F_0PAD) {
				c = '0';
				PAD(width - realsz, c);
			}
			
			/*
			 * FIXME: floating point
			 */

			/* a string */
			PUT(cp, size);

			if (flags & F_LEFT) {
				c = ' ';
				PAD(width - realsz, c);
			}
			
			/* Switch to initial state */
			fmt++;
			newstate(INI);
		}
	}
error:
	FLUSH();
	return ret;
}

int
radvsprintf(string, size, fmt, ap)
	char   *string;
	size_t size;
	char   *fmt;
	va_list ap;
{
	IO_BUF b;

	b.type = IO_STRING;
	b.io_base = string;
	b.io_size = size;
	b.io_level = 0;
	return radprint(&b, fmt, ap);
}	

/*PRINTFLIKE3*/
int
radsprintf(string, size, fmt, va_alist)
	char   *string;
	size_t size;
	char   *fmt;
	va_dcl
{
	va_list ap;
	int rc;

	va_start(ap);
	rc = radvsprintf(string, size, fmt, ap);
	va_end(ap);
	return rc;
}

int
radvfprintf(file, fmt, ap)
	FILE *file;
	char   *fmt;
	va_list ap;
{
	IO_BUF b;
	int rc;
	char filebuf[256];
	
	b.type = IO_FILE;
	b.io_stream = file;
	b.io_base = filebuf;
	b.io_size = sizeof(filebuf);
	b.io_level = 0;
	rc = radprint(&b, fmt, ap);
	fflush(file);
	return rc;
}	

/*PRINTFLIKE2*/
int
radfprintf(file, fmt, va_alist)
	FILE *file;
	char   *fmt;
	va_dcl
{
	va_list ap;
	int rc;
	
	va_start(ap);
	rc = radvfprintf(file, fmt, ap);
	va_end(ap);
	return rc;
}	

#ifdef STANDALONE
main()
{
	char string[1800];
	int sentinel = 0;
	VALUE_PAIR *spair,*ipair,*lpair,*dpair;
	unsigned long i = 273;
	
	radpath_init();
	dict_init();
#if 1
	spair = avp_create(DA_USER_NAME, strlen("gray"), "gray", 0);
	ipair = avp_create(DA_FRAMED_IP_ADDRESS, 0, NULL, 0x7f101001);
	dpair = avp_create(DA_FRAMED_PROTOCOL, 0, NULL, 1);
	lpair = avp_create(DA_SIMULTANEOUS_USE, 0, NULL, 1);
	i = radsprintf(string, sizeof(string),
		   "a decimal '%+d, octal %#o, hex %#X, string '%4.4s' ;\n"
		   "varstr '%*.*s'.\n"
		   "character %c\n"
		   "pointer %34p\n"
		   "pair %A,%A,%A,%A\n"
		   "IP %I.\n",
		   -6,
		   10,
		   65435, "STRING",
		   15, 10, "bloomsday", 'e',
		   (void*)-1,
		   spair,ipair,lpair,dpair,
		   0x7f000001);
#endif
	printf("%s\n", string);
	printf("out: %d -- %d\n", i, strlen(string));
	printf("sentinel %d\n", sentinel);

}
#endif

