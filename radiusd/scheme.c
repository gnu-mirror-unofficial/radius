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

#ifdef USE_SERVER_GUILE

#include <radiusd.h>
#include <libguile.h>
#include <setjmp.h>

/* Protos to be moved to radscm */
SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);

/* Static declarations */
static void *guile_boot0(void *ignored);
static void guile_boot1(void *closure, int argc, char **argv);

pth_t guile_tid;
pth_msgport_t guile_mp;

struct call_data {
	pth_message_t head;
	int retval;
	int (*fun)(struct call_data*);
	char *procname;
	RADIUS_REQ *request;
	VALUE_PAIR *user_check;
	VALUE_PAIR **user_reply_ptr;
};
	
/* ************************************************************************* */
/* Boot up stuff */

void
start_guile()
{
	pth_attr_t attr = pth_attr_new();
	pth_attr_set(attr, PTH_ATTR_STACK_SIZE, 1024*1024);
	guile_tid = pth_spawn(PTH_ATTR_DEFAULT, guile_boot0, NULL);
	if (!guile_tid) 
		radlog(L_ERR|L_PERROR, _("Can't spawn guile thread"));
	pth_yield(guile_tid);
}

void *
guile_boot0(arg)
	void *arg;
{
	char *argv[] = { "radiusd", NULL };
	scm_boot_guile (1, argv, guile_boot1, arg);
	return NULL;
}	

static SCM
boot_body (void *data)
{
	struct call_data *p;
	static pth_key_t ev_key = PTH_KEY_INIT;
	pth_event_t ev;

	guile_mp = pth_msgport_create("guile");
	ev = pth_event(PTH_EVENT_MSG|PTH_MODE_STATIC, &ev_key, guile_mp);

	scm_init_load_path();
	radscm_init();
	rscm_radlog_init();
	rscm_rewrite_init();

	while (1) {
		pth_wait(ev);
		p = (struct call_data*) pth_msgport_get(guile_mp);
		p->retval = p->fun(p);
		pth_msgport_reply((pth_message_t*)p);
	}
	
	return SCM_BOOL_F;
}

static SCM
boot_handler (void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}

void
guile_boot1(closure, argc, argv)
	void *closure;
	int argc;
	char **argv;
{
	scm_internal_catch(SCM_BOOL_T,
			   boot_body, closure,
			   boot_handler, NULL);
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
		

/* ************************************************************************* */
/* Functions running in Guile thread address space */

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
scheme_auth_internal(p)
	struct call_data *p;
{
	SCM s_request, s_check, s_reply;
	SCM res, env;
	SCM procsym;
	jmp_buf jmp_env;
	
	s_request = radscm_avl_to_list(p->request->request);
	s_check = radscm_avl_to_list(p->user_check);
	s_reply = radscm_avl_to_list(*p->user_reply_ptr);

	/* Evaluate the procedure */
	procsym = scm_symbol_value0 (p->procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		radlog(L_ERR,
		       _("%s is not a procedure object"), p->procname);
		return 1;
	}
	if (setjmp(jmp_env)) 
		return 1;

	res = scm_internal_lazy_catch(
		SCM_BOOL_T,
		eval_catch_body,
		(void*) SCM_LIST4(procsym,
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      s_request,
					      SCM_UNDEFINED),
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      s_check,
					      SCM_UNDEFINED),
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      s_reply,
					      SCM_UNDEFINED)),
		eval_catch_handler, &jmp_env);
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	if (SCM_NIMP(res) && SCM_CONSP(res)) {
		int code = SCM_CAR(res);
		VALUE_PAIR *list = radscm_list_to_avl(SCM_CDR(res));
		avl_merge(p->user_reply_ptr, &list);
		avl_free(list);
		return code == SCM_BOOL_F;
	}
	/*FIXME: message*/
	return 1;
}


int
scheme_acct_internal(p)
	struct call_data *p;
{
	SCM procsym, res;
	jmp_buf jmp_env;
	SCM s_request = radscm_avl_to_list(p->request->request);

	/* Evaluate the procedure */
	procsym = scm_symbol_value0 (p->procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		radlog(L_ERR,
		       _("%s is not a procedure object"), p->procname);
		return 1;
	}
	if (setjmp(jmp_env))
		return 1;
	res = scm_internal_lazy_catch(
		SCM_BOOL_T,
		eval_catch_body,
		(void*) SCM_LIST2(procsym,
				  scm_listify(SCM_IM_QUOTE,
					      s_request,
					      SCM_UNDEFINED)),
		eval_catch_handler, &jmp_env);
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	return 1;
}

int
scheme_end_reconfig_internal(p)
	struct call_data *p;
{
	scm_gc();
	return 0;
}

void
scheme_load_internal(p)
	struct call_data *p;
{
	scm_primitive_load_path(scm_makfrom0str(p->procname));
}


/* ************************************************************************* */
/* Functions running in arbitrary address space */

int
scheme_generic_call(fun, procname, req, user_check, user_reply_ptr)
	int (*fun)();
	char *procname;
	RADIUS_REQ *req;
	VALUE_PAIR *user_check;
	VALUE_PAIR **user_reply_ptr;
{
	struct call_data *p = emalloc(sizeof(*p));
	static pth_key_t ev_key = PTH_KEY_INIT;
	pth_event_t ev;
	pth_msgport_t mp;
	int rc;
	
	mp = pth_msgport_create("scheme_call");
	p->head.m_replyport = mp;
	p->fun = fun;
	p->procname = procname;
	p->request = req;
	p->user_check = user_check;
	p->user_reply_ptr = user_reply_ptr;

	pth_msgport_put(guile_mp, (pth_message_t*)p);
	ev = pth_event(PTH_EVENT_MSG|PTH_MODE_STATIC, &ev_key, mp);
	pth_wait(ev);
	pth_msgport_get(mp);
	pth_msgport_destroy(mp);
	rc = p->retval;
	efree(p);
	return rc;
}

void
scheme_load(filename)
	char *filename;
{
	scheme_generic_call(scheme_load_internal, filename, NULL, NULL, NULL);
}

int
scheme_end_reconfig()
{
	scheme_generic_call(scheme_end_reconfig_internal,
			    NULL, NULL, NULL, NULL);
}


int
scheme_auth(procname, req, user_check, user_reply_ptr)
	char *procname;
	RADIUS_REQ *req;
	VALUE_PAIR *user_check;
	VALUE_PAIR **user_reply_ptr;
{
	return scheme_generic_call(scheme_auth_internal,
				   procname, req, user_check, user_reply_ptr);
}

int
scheme_acct(procname, req)
	char *procname;
	RADIUS_REQ *req;
{
	return scheme_generic_call(scheme_acct_internal,
				   procname, req, NULL, NULL);
}

void
scheme_read_eval_loop()
{
	SCM list;
	int status;
	SCM sym_top_repl = scm_symbol_value0("top-repl");
	SCM sym_begin = scm_symbol_value0("begin");
	
	list = scm_cons(sym_begin, SCM_LIST1(scm_cons(sym_top_repl, SCM_EOL)));
	status = scm_exit_status(scm_eval_x(list));
	printf("%d\n", status);
}

#endif
