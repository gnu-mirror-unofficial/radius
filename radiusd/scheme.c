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

static SCM
catch_body (void *data)
{
	radscm_init();
	rscm_radlog_init();
	scm_init_load_path();
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
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		radlog(L_ERR,
		       _("procname is not a procedure object"));
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
		avl_merge(user_reply_ptr, &list);
		avl_free(list);
		return code == SCM_BOOL_F;
	}
	/*FIXME: message*/
	return 1;
}

int
scheme_acct(procname, req)
	char *procname;
	RADIUS_REQ *req;
{
	SCM procsym, res;
	jmp_buf jmp_env;
	SCM s_request = radscm_avl_to_list(req->request);

	/* Evaluate the procedure */
	procsym = scm_symbol_value0 (procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		radlog(L_ERR,
		       _("%s is not a procedure object"), procname);
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


void
scheme_load(filename)
	char *filename;
{
	scm_primitive_load_path(scm_makfrom0str(filename));
}



#endif
