/* This file is part of GNU RADIUS.
   Copyright (C) 2002, Free Software Foundation
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <netinet/in.h>

#include <radius.h>
#include <obstack1.h>
#include <radutmp.h>
#include <pwd.h>
#include <stdio.h>

#define TAB_SIZE 8 /* FIXME */

#define ALIGN_LEFT 0
#define ALIGN_RIGHT 1

int printutmp_ip_nodomain; /* do not display domain names */
int printutmp_use_naslist = 1; /* use naslist when displaying nas names */
char *printutmp_date_format = "%a %H:%M";
char *printutmp_empty_string = "";

static struct obstack stk;

#define FDATA_FH 0
#define FDATA_STRING 1
#define FDATA_TAB 2 
#define FDATA_NEWLINE 3

typedef struct format_key format_key_t;
struct format_key {
	format_key_t *next;
	char *name;
	char *value;
};

typedef int (*radutent_fh_t)(int outbytes, int width, format_key_t *key,
			     struct radutmp *up);

struct format_data {
	format_data_t *next;
	int type;
	format_key_t *key;
	union {
		struct {
			radutent_fh_t fun;
			int width;
			char *header;
		} fh;              /* FDATA_FH */
		char *string;      /* FDATA_STRING */
		int tabstop;       /* FDATA_TAB */
		int nl;            /* FDATA_NEWLINE */
	} v;
};


int output_string(char *string, int width, int align);
int output_string_key(char *string, int width, format_key_t *key);
int output_tab(int column, int tabstop);
int output_hostname(UINT4 ip, int width, format_key_t *key);
int output_time(time_t t, int width, format_key_t *key);
char *get_hostname(UINT4 ipaddr, int nodomain, char *buf, size_t size);

static void format_key_free(format_key_t *key);
static char *format_key_lookup(format_key_t *key, char *name);
static int key_align(format_key_t *key);
static char *key_date_format(format_key_t *key);
static char *key_empty(format_key_t *key);
static int key_nodomain(format_key_t *key);

void
format_key_free(key)
	format_key_t *key;
{
	format_key_t *next;
	while (key) {
		next = key->next;
		efree(key->name);
		efree(key->value);
		efree(key);
		key = next;
	}
}

char *
format_key_lookup(key, name)
	format_key_t *key;
	char *name;
{
	for (; key; key = key->next) {
		if (strcmp(key->name, name) == 0)
			return key->value;
	}
	return NULL;
}

void
form_free(form)
	format_data_t *form;
{
	format_data_t *next;

	while (form) {
		next = form->next;
		
		format_key_free(form->key);
		switch (form->type) {
		case FDATA_STRING:
			efree(form->v.string);
			break;
		case FDATA_FH:
			efree(form->v.fh.header);
			break;
		default:
			break;
		}
		efree(form);

		form = next;
	}
}

static int
key_align(key)
	format_key_t *key;
{
	char *p = format_key_lookup(key, "right");
	return p ? ALIGN_RIGHT : ALIGN_LEFT;
}

static char *
key_date_format(key)
	format_key_t *key;
{
	char *p = format_key_lookup(key, "format");
	return p ? p : printutmp_date_format;
}

static char *
key_empty(key)
	format_key_t *key;
{
	char *p = format_key_lookup(key, "empty");
	return p ? p : printutmp_empty_string;
}

static int
key_nodomain(key)
	format_key_t *key;
{
	char *p = format_key_lookup(key, "nodomain");
	return p ? 1 : printutmp_ip_nodomain;
}

int
output_string(string, width, align)
	char *string;
	int width;
	int align;
{
	if (width == 0) 
		width = printf("%s", string);
	else if (align == ALIGN_LEFT)
		width = printf("%-*.*s", width, width, string);
	else
		width = printf("%*.*s", width, width, string);
	return width;
}

int
output_string_key(string, width, key)
	char *string;
	int width;
	format_key_t *key;
{
	if (strlen(string) == 0)
		string = key_empty(key);
	return output_string(string, width, key_align(key));
}


int
output_tab(column, tabstop)
	int column;
	int tabstop;
{
	int goal = (((column + TAB_SIZE - 1) / TAB_SIZE) + tabstop) * TAB_SIZE;
	for (;column < goal; column++)
		putchar(' ');
	return column;
}

char *
get_hostname(ipaddr, nodomain, buf, size)
        UINT4 ipaddr;
	int nodomain;
        char *buf;
        size_t size;
{
        if (ipaddr == 0 || ipaddr == (UINT4)-1 || ipaddr == (UINT4)-2)
                return "";

        if (nodomain) {
		char *s, *p;
                s = ip_gethostname(ntohl(ipaddr), buf, size);
                for (p = s; *p && (isdigit(*p) || *p == '.'); p++)
                        ;
                if (*p == 0)
                        return s;
                if ((p = strchr(s, '.')) != NULL)
                        *p = 0;
                return s;
	}
	
	return ip_gethostname(ntohl(ipaddr), buf, size);
}

int
output_hostname(ip, width, key)
	UINT4 ip;
	int width;
	format_key_t *key;
{
	char buf[80];
	return output_string_key(get_hostname(ip, key_nodomain(key),
					      buf, sizeof buf), width, key);
}

/*FIXME: ignores key */
int
output_time(t, width, key)
	time_t t;
	int width;
	format_key_t *key;
{
        int d,h,m,s;
	
        d = t / 86400;
        t %= 86400;
        
        s = t % 60;
        m = t / 60;
        if (m > 59) {
                h = m / 60;
                m -= h*60;
        } else
                h = 0;
	if (d)
		width = printf("%d+%02d:%02d", d, h, m);
        else
                width = printf("%02d:%02d", h, m);
	return width;
}

/*ARGSUSED*/
int
login_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_string_key(up->login, width, key);
}

/*ARGSUSED*/
int
orig_login_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_string_key(up->orig_login, width, key);
}

/*ARGSUSED*/
int
gecos_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
        struct passwd *pwd;
        char *s;

        if ((pwd = getpwnam(up->login)) != NULL) {
                if ((s = strchr(pwd->pw_gecos, ',')) != NULL)
                        *s = 0;
                s = pwd->pw_gecos;
        } else
                s = up->orig_login;
	return output_string_key(s, width, key);
}

/*ARGSUSED*/
int
nas_port_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	char buf[6];
	
	sprintf(buf, "%0*d", width, up->nas_port);
	return output_string_key(buf, width, key);
}

/*ARGSUSED*/
int
session_id_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_string_key(up->session_id, width, key);
}

/*ARGSUSED*/
int
nas_address_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	if (printutmp_use_naslist) {
		NAS *nas;
	
		nas = nas_lookup_ip(ntohl(up->nas_address));
		if (!nas)
			return output_hostname(up->nas_address, width, key);
		return output_string_key(nas->shortname[0] ?
			       nas->shortname : nas->longname, width, key);
	}
	return output_hostname(up->nas_address, width, key);
}

/*ARGSUSED*/
int
framed_address_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_hostname(up->framed_address, width, key);
}

/*ARGSUSED*/
int
protocol_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	DICT_VALUE *dval = value_lookup(up->proto, "Framed-Protocol");
	char buf[80];
	char *s;
	
        if (dval)
		s = dval->name;
	else {
                snprintf(buf, sizeof(buf), "%u", up->proto);
		s = buf;
	}
	return output_string_key(s, width, key);
}

/*ARGSUSED*/
int
time_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
        char buf[80];
	
	strftime(buf, sizeof buf, key_date_format(key), localtime(&up->time));
	return output_string_key(buf, width, key);
}

/*ARGSUSED*/
int
duration_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_time((up->type == P_IDLE) ?
			   up->duration : time(NULL) - up->time,
			   width, key);
}

/*ARGSUSED*/
int
delay_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_time(up->delay, width, key);
}

/*ARGSUSED*/
int
port_type_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	DICT_VALUE *dval = value_lookup(up->porttype, "NAS-Port-Type");
	char buf[80];
	char *s;
	
        if (dval)
		s = dval->name;
	else {
                snprintf(buf, sizeof(buf), "%u", up->porttype);
		s = buf;
	}
	return output_string_key(s, width, key);
}

/*ARGSUSED*/
int
clid_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
	return output_string_key(up->caller_id, width, key);
}

/*ARGSUSED*/
int
realm_address_fh(outbytes, width, key, up)
	int outbytes;
	int width;
	format_key_t *key;
	struct radutmp *up;
{
        if (up->realm_address == 0)
		return output_string_key("", width, key);
	else {
		REALM *rp = realm_lookup_ip(up->realm_address);
		if (rp)
			return output_string_key(rp->realm, width, key);
	}
	return output_hostname(up->realm_address, width, key);
}

static struct {
	char *name;
	radutent_fh_t fun;
} handlers[] = {
	"login",  login_fh,
	"orig-login", orig_login_fh,
	"gecos", gecos_fh,
	"nas-port", nas_port_fh,
	"session-id", session_id_fh,
	"nas-address", nas_address_fh,
	"framed-address", framed_address_fh,
	"protocol", protocol_fh,
	"time", time_fh,
	"duration", duration_fh,
	"delay", delay_fh,
	"port-type", port_type_fh,
	"clid", clid_fh,
	"realm", realm_address_fh,
	NULL
};

static radutent_fh_t 
_lookup(name)
	char *name;
{
	int i;
	for (i = 0; handlers[i].name; i++)
		if (strcmp(handlers[i].name, name) == 0)
			return handlers[i].fun;
	return NULL;
}

static char *
parse_string0(fmt, form, cond, closure)
	char *fmt;
	format_data_t *form;
	int (*cond)();
	void *closure;
{
	char *p;
	
	for (p = fmt; *p && (*cond)(closure, p) == 0; p++) {
		if (*p == '\\') {
			int c;
			switch (*++p) {
			case 'a':
				c = '\a';
				break;
			case 'b':
				c = '\b';
				break;
			case 'e':
				c = '\033';
				break;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 't':
				c = '\t';
				break;
			case 'r':
				c = '\r';
				break;
			case 'v':
				c = '\v';
				break;
			default:
				c = *p;
			}
			obstack_1grow(&stk, c);
		} else
			obstack_1grow(&stk, *p);
	}

	form->type = FDATA_STRING;
	form->v.string = estrdup(obstack_finish(&stk));
	return p;
}

static int
_is_closing_quote(closure, p)
	void *closure;
	char *p;
{
	return *(char*)closure == *p;
}

static int
parse_quote(fmtp, form)
	char **fmtp;
	format_data_t *form;
{
	char *p;
	p = parse_string0(*fmtp + 1, form, _is_closing_quote, *fmtp);	
	if (!*p) {
		radlog(L_ERR,
		       _("missing closing quote in string started near `%s'"),
		       *fmtp);
		return 1;
	}
	*fmtp = p + 1;
	return 0;
}

/*ARGSUSED*/
static int
_is_delim(closure, p)
	void *closure;
	char *p;
{
	return *p == '(';
}

static int
parse_string(fmtp, form)
	char **fmtp;
	format_data_t *form;
{
	char *p;
	p = parse_string0(*fmtp, form, _is_delim, NULL);
	*fmtp = p;
	return 0;
}

static char *
get_token(fmtp)
	char **fmtp;
{
	char *p;

	while (**fmtp && isspace(**fmtp))
		++*fmtp;
	p = *fmtp;
	if (*p == ')') {
		obstack_1grow(&stk, *p);
		++*fmtp;
	} else {
		while (**fmtp && !isspace(**fmtp) && **fmtp != ')')
			++*fmtp;
		obstack_grow(&stk, p, *fmtp - p);
	}
	obstack_1grow(&stk, 0);
	return obstack_finish(&stk);
}

static int
parse_form(fmtp, form)
	char **fmtp;
	format_data_t *form;
{
	char *formname, *p;
	format_key_t *key_head, *key_tail;
	
	++*fmtp;

	formname = get_token(fmtp);
	if (strcmp(formname, "newline") == 0) {
		form->type = FDATA_NEWLINE;
		p = get_token(fmtp);
		if (p[0] != ')') {
			form->v.nl = strtol(p, NULL, 0);
			p = get_token(fmtp);
		} else
			form->v.nl = 1;
	} else if (strcmp(formname, "tab") == 0) {
		form->type = FDATA_TAB;
		p = get_token(fmtp);
		if (p[0] != ')') {
			form->v.tabstop = strtol(p, NULL, 0);
			p = get_token(fmtp);
		} else
			form->v.tabstop = 1;
	} else {
		radutent_fh_t fh;
		int arg;
		
		fh = _lookup(formname);
		if (!fh) {
			radlog(L_ERR,
			       _("error in format spec: unknown format %s"),
			       formname);
			return 1;
		}
		
		form->type = FDATA_FH;
		form->v.fh.fun = fh;

		/* Collect optional arguments */
		arg = 0;
		while ((p = get_token(fmtp)) != NULL &&
		       !(p[0] == ':' || p[0] == ')')) {
			arg++;
			switch (arg) {
			case 1: /* width */
				form->v.fh.width = strtol(p, NULL, 0);
				break;
			case 2: /* header */
				form->v.fh.header = estrdup(p);
				break;
			default:
				radlog(L_ERR,
				    _("wrong number of arguments to form %s"),
				       formname);
				return 1;
			}
		}
		
		/* Collect keyword arguments */
		key_head = NULL;
		while (p && p[0] == ':') {
			format_key_t *key = emalloc(sizeof(*key));
			if (!key_head)
				key_head = key;
			else
				key_tail->next = key;
			key_tail = key;
			key->name = estrdup(p+1);
			p = get_token(fmtp);
			if (p[0] == ')' || p[0] == ':')
				key->value = estrdup("t");
			else {
				key->value = estrdup(p);
				p = get_token(fmtp);
			}
		}
		form->key = key_head;
	}
	
	if (p[0] != ')') {
		radlog(L_ERR, _("form `%s' not closed"), formname);
		return 1;
	}
	return 0;
}

format_data_t *
radutent_compile_form(fmt)
	char *fmt;
{
	format_data_t *form_head = NULL, *form_tail;
	
	obstack_init(&stk);
	while (*fmt) {
		int rc;
		
		format_data_t *form = emalloc(sizeof(*form));
		if (!form_head)
			form_head = form;
		else
			form_tail->next = form;
		form_tail = form;

		if (*fmt == '(')
			rc = parse_form(&fmt, form);
		else if (*fmt == '"' || *fmt == '\'')
			rc = parse_quote(&fmt, form);
		else
			rc = parse_string(&fmt, form);
		
		if (rc) {
			form_free(form_head);
			form_head = NULL;
			break;
		}
	}

	obstack_free(&stk, NULL);
	
	return form_head;
}

int
radutent_print(form, up, newline)
	format_data_t *form;
	struct radutmp *up;
	int newline;
{
	int i;
	int outbytes = 0;

	for (; form; form = form->next) {
		switch (form->type) {
		case FDATA_FH:
			outbytes += form->v.fh.fun(outbytes,
						   form->v.fh.width,
						   form->key,
						   up);
			break;
				
		case FDATA_STRING:
			outbytes += output_string(form->v.string, 0, ALIGN_LEFT);
			break;
			
		case FDATA_TAB:
			outbytes += output_tab(outbytes, form->v.tabstop);
			break;

		case FDATA_NEWLINE:
			for (i = 0; i < form->v.nl; i++)
				putchar('\n');
			break;
			
		default:
			abort();
		}
	}
	if (newline)
		putchar('\n');
	return outbytes;
}

void
printutmp_header(form)
	format_data_t *form;
{
	int i, outbytes = 0;
	format_data_t *p;

	for (p = form; p; p = p->next) 
		if (p->type == FDATA_NEWLINE)
			return;
	
	for (; form; form = form->next) {
		switch (form->type) {
		case FDATA_FH:
			if (form->v.fh.header)
				outbytes += output_string(form->v.fh.header,
							  form->v.fh.width,
							  ALIGN_LEFT);
			else
				outbytes += form->v.fh.width;
			break;
				
		case FDATA_STRING:
			outbytes += output_string("",
						  strlen(form->v.string),
						  ALIGN_LEFT);
			break;
			
		case FDATA_TAB:
			outbytes += output_tab(outbytes, form->v.tabstop);
			break;

		case FDATA_NEWLINE:
			for (i = 0; i < form->v.nl; i++)
				putchar('\n');
			break;
			
		default:
			abort();
		}
	}
	putchar('\n');
}

