/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
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
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius.h>
#include <radscm.h>

SCM 
scm_makenum (val)
	unsigned long val;
{
  if (SCM_FIXABLE ((long) val))
    return SCM_MAKINUM (val);

#ifdef SCM_BIGDIG
  return scm_long2big (val);
#else /* SCM_BIGDIG */
  return scm_make_real ((double) val);
#endif /* SCM_BIGDIG */
}

SCM
radscm_avl_to_list(pair)
	VALUE_PAIR *pair;
{
	SCM scm_first = SCM_EOL, scm_last, new;
	
	for (; pair; pair = pair->next) {
		SCM_NEWCELL(new);
		SCM_SETCAR(new, radscm_avp_to_cons(pair));
		if (scm_first == SCM_EOL) {
			scm_last = scm_first = new;
		} else {
			SCM_SETCDR(scm_last, new);
			scm_last = new;
		}
	}
	if (scm_first != SCM_EOL)
		SCM_SETCDR(scm_last, SCM_EOL);
	return scm_first;
}

VALUE_PAIR *
radscm_list_to_avl(list)
	SCM list;
{
	VALUE_PAIR *first, *last, *p;

	if (list == SCM_EOL)
		return NULL;
	first = last = NULL;
	do {
		p = radscm_cons_to_avp(SCM_CAR(list));
		if (p) {
			p->next = NULL;
			if (!last)
				first = p;
			else
				last->next = p;
			last = p;
		}
		list = SCM_CDR(list);
	} while (list != SCM_EOL);
	return first;
}


SCM
radscm_avp_to_cons(pair)
	VALUE_PAIR *pair;
{
	SCM scm_attr, scm_value;
	DICT_ATTR *dict;
	
	if (dict = attr_number_to_dict(pair->attribute)) 
		scm_attr = scm_makfrom0str(dict->name);
	else
		scm_attr = SCM_MAKINUM(pair->attribute);
	switch (pair->type) {
	case TYPE_STRING:
	case TYPE_DATE:
		scm_value = scm_makfrom0str(pair->strvalue);
		break;
	case TYPE_INTEGER:
		scm_value = scm_makenum(pair->lvalue);
		break;
	case TYPE_IPADDR:
		scm_value = scm_ulong2num(pair->lvalue);
		break;
	default:
		abort();
	}

	return scm_cons(scm_attr, scm_value);
}

/*
 * (define scm (cons NAME VALUE))
 */

VALUE_PAIR *
radscm_cons_to_avp(scm)
	SCM scm;
{
	SCM car, cdr;
	DICT_ATTR *dict;
	DICT_VALUE *val;
	VALUE_PAIR pair, *p;
	
	if (!(SCM_NIMP(scm) && SCM_CONSP(scm)))
		return NULL;

	car = SCM_CAR(scm);
	cdr = SCM_CDR(scm);
	memset(&pair, 0, sizeof(pair));
	if (SCM_IMP(car) && SCM_INUMP(car)) {
		pair.attribute = SCM_INUM(car);
		dict = attr_number_to_dict(pair.attribute);
		if (!dict) 
			return NULL;
		pair.name = dict->name;
	} else if (SCM_NIMP(car) && SCM_STRINGP(car)) {
		pair.name = SCM_CHARS(car);
		dict = attr_name_to_dict(pair.name);
		if (!dict) 
			return NULL;
		pair.attribute = dict->value;
	} else
		return NULL;
	
	pair.type = dict->type;
	pair.operator = OPERATOR_EQUAL;
	pair.type = dict->type;
	pair.prop = dict->prop;

	switch (pair.type) {
	case TYPE_INTEGER:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair.lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair.lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			char *name = SCM_CHARS(cdr);
			val = value_name_to_value(name, pair.attribute);
			if (val) {
				pair.lvalue = val->value;
			} else {
				pair.lvalue = strtol(name, &name, 0);
				if (*name)
					return NULL;
			}
		} else
			return NULL;
		break;
		
	case TYPE_IPADDR:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair.lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair.lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			pair.lvalue = get_ipaddr(SCM_CHARS(cdr));
		} else
			return NULL;
		break;
	case TYPE_STRING:
	case TYPE_DATE:
		if (!(SCM_NIMP(cdr) && SCM_STRINGP(cdr)))
			return NULL;
		pair.strvalue = make_string(SCM_CHARS(cdr));
		pair.strlength = strlen(pair.strvalue);
		break;
	default:
		abort();
	}

	p = alloc_entry(sizeof(VALUE_PAIR));
	*p = pair;
	
	return p;
}

void
radscm_init()
{
	rscm_syslog_init();
	rscm_utmp_init();
	rscm_avl_init();
	rscm_dict_init();
#include <rscm_lib.x>
}
