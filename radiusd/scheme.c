/* This file is part of GNU Radius.
   Copyright (C) 2001,2002,2003 Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_SCHEME_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef USE_SERVER_GUILE

#include <unistd.h>
#include <radiusd.h>
#include <libguile.h>
#include <radscm.h>
#include <setjmp.h>
#include <errno.h>

/* Protos to be moved to radscm */
SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);

static SCM
catch_body(void *data)
{
	scm_init_load_path();
	radscm_init();
	rscm_radlog_init();
	rscm_rewrite_init();
	rad_mainloop(data);
	return SCM_BOOL_F;
}

static SCM
catch_handler(void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}


void
rad_boot(void *closure, int argc, char **argv)
{
	scm_internal_catch(SCM_BOOL_T,
			   catch_body, closure,
			   catch_handler, NULL);
}

void
scheme_debug(int val)
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
scheme_auth(char *procname, RADIUS_REQ *req, 
	    VALUE_PAIR *user_check,
	    VALUE_PAIR **user_reply_ptr)
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
scheme_acct(char *procname, RADIUS_REQ *req)
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
scheme_load(char *filename)
{
	scm_primitive_load_path(scm_makfrom0str(filename));
}

void
scheme_end_reconfig()
{
	scm_gc();
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


/* *************************** Configuration ******************************* */

int
guile_cfg_handler(int argc ARG_UNUSED, cfg_value_t *argv ARG_UNUSED,
		  void *block_data ARG_UNUSED, void *handler_data ARG_UNUSED)
{
	use_guile = 1;
	return 0;
}

static int
scheme_cfg_add_load_path(int argc, cfg_value_t *argv,
			 void *block_data, void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}

	scheme_add_load_path(argv[1].v.string);
	return 0;
}

static int
scheme_cfg_load(int argc, cfg_value_t *argv, void *block_data,
		void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	scheme_load(argv[1].v.string);
	return 0;
}

static int
scheme_cfg_debug(int argc, cfg_value_t *argv,
		 void *block_data, void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_BOOLEAN) {
		cfg_type_error(CFG_BOOLEAN);
		return 0;
	}
	scheme_debug(argv[1].v.bool);
	return 0;
}

struct cfg_stmt guile_stmt[] = {
	{ "load-path", CS_STMT, NULL, scheme_cfg_add_load_path, NULL, NULL, NULL },
	{ "load", CS_STMT, NULL, scheme_cfg_load, NULL, NULL, NULL },
	{ "debug", CS_STMT, NULL, scheme_cfg_debug, NULL, NULL, NULL },
	{ "gc-interval", CS_STMT, NULL, cfg_get_integer, &scheme_gc_interval,
	  NULL, NULL },
	{ "task-timeout", CS_STMT, NULL, cfg_get_integer, &scheme_task_timeout,
	  NULL, NULL},
	{ NULL }
};


#endif
