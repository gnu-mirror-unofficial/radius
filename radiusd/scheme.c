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

#ifdef USE_GUILE

#include <radiusd.h>
#include <libguile.h>
#include <setjmp.h>

/* Protos to be moved to radscm */
SCM  scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);

static SCM
catch_body (void *data)
{
	rad_mainloop();
	return SCM_BOOL_F;
}

static SCM
catch_handler (void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}


void
rad_boot()
{
	scm_internal_catch(SCM_BOOL_T,
			   catch_body, NULL,
			   catch_handler, NULL);
}

void
scheme_debug(val)
	int val;
{
	SCM_DEVAL_P = val;
	SCM_BACKTRACE_P = val;
	SCM_RECORD_POSITIONS_P = val;
	SCM_RESET_DEBUG_MODE;
}
		

static SCM
eval_catch_body (void *list)
{
	return scm_eval((SCM)list);
}

static SCM
eval_catch_handler (void *data, SCM tag, SCM throw_args)
{
	scm_handle_by_message_noexit("radiusd", tag, throw_args);
	longjmp(*(jmp_buf*)data, 1);
}

int
scheme_auth(procname, req, user_check, user_reply_ptr)
	char *procname;
	RADIUS_REQ *req;
	VALUE_PAIR *user_check;
	VALUE_PAIR **user_reply_ptr;
{
	SCM s_request, s_check, s_reply;
	SCM res, env;
	SCM procsym;
	jmp_buf jmp_env;
	
	s_request = radscm_avl_to_list(req->request);
	s_check = radscm_avl_to_list(user_check);
	s_reply = radscm_avl_to_list(*user_reply_ptr);

	/* Evaluate the procedure */
	procsym = scm_symbol_value0 (procname);
	if (setjmp(jmp_env))
		return 1;
	res = scm_internal_lazy_catch(SCM_BOOL_T,
				      eval_catch_body,
				      (void*)SCM_LIST4(procsym,
						       scm_cons (SCM_IM_QUOTE,
								 s_request),
						       scm_cons (SCM_IM_QUOTE,
								 s_check),
						       scm_cons (SCM_IM_QUOTE,
								 s_reply)),
				      eval_catch_handler, &jmp_env);
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	if (SCM_NIMP(res) && SCM_CONSP(res)) {
		int code = SCM_CAR(res);
		VALUE_PAIR *list = radscm_list_to_avl(SCM_CDR(res));
		avl_merge(user_reply_ptr, &list);
		avl_free(list);
		return res == SCM_BOOL_F;
	}
	/*FIXME: message*/
	return 1;
}

void
scheme_load(filename)
	char *filename;
{
	scm_primitive_load_path(scm_makfrom0str(filename));
}

void
scheme_load_path(path)
	char *path;
{
	SCM scm, *scm_loc;
	scm_loc = SCM_CDRLOC (scm_sysintern ("%load-path", SCM_EOL));
	*scm_loc = scm_cons(scm_makfrom0str(path),
			    scm_symbol_value0("%load-path"));
}

/* The functions below belong to libradscm: */
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
	SCM scm_first = SCM_EOL, scm_last, scm_attr, scm_value, new;
	
	for (; pair; pair = pair->next) {
		new = radscm_avp_to_cons(pair);
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
	SCM scm_value, new;

	switch (pair->type) {
	case PW_TYPE_STRING:
	case PW_TYPE_DATE:
		scm_value = scm_makfrom0str(pair->strvalue);
		break;
	case PW_TYPE_INTEGER:
		scm_value = scm_makenum(pair->lvalue);
		break;
	case PW_TYPE_IPADDR:
		scm_value = scm_ulong2num(pair->lvalue);
		break;
	default:
		abort();
	}

	SCM_NEWCELL(new);
	SCM_SETCAR(new, scm_cons(scm_makenum(pair->attribute), scm_value));
	return new;
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
	pair.operator = PW_OPERATOR_EQUAL;

	switch (pair.type) {
	case PW_TYPE_INTEGER:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair.lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair.lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			char *name = SCM_CHARS(cdr);
			val = value_name_to_value(name);
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
		
	case PW_TYPE_IPADDR:
		if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
			pair.lvalue = SCM_INUM(cdr);
		} else if (SCM_BIGP(cdr)) {
			pair.lvalue = (UINT4) scm_big2dbl(cdr);
		} else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
			pair.lvalue = get_ipaddr(SCM_CHARS(cdr));
		} else
			return NULL;
		break;
	case PW_TYPE_STRING:
	case PW_TYPE_DATE:
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

#endif
