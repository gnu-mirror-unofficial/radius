/* This file is part of GNU Radius.
   Copyright (C) 2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef USE_SERVER_GUILE

#include <unistd.h>
#include <fcntl.h>
#include <radiusd.h>
#include <libguile.h>
#include <setjmp.h>
#include <errno.h>

#include <radius/radscm.h>

static unsigned scheme_gc_interval = 3600;
static char *scheme_outfile = NULL;
static SCM scheme_error_port = SCM_EOL;

/* Protos to be moved to radscm */
SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(grad_avp_t *pair);
grad_avp_t *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(grad_avp_t *pair);
grad_avp_t *radscm_cons_to_avp(SCM scm);

static SCM
catch_body(void *data)
{
	scm_init_load_path();
	grad_scm_init();
	rscm_server_init();
	scm_c_use_module("radiusd");
	radiusd_main();
	return SCM_BOOL_F;
}

static SCM
catch_handler(void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}


void
scheme_boot(void *closure, int argc, char **argv)
{
	scm_internal_catch(SCM_BOOL_T,
			   catch_body, closure,
			   catch_handler, NULL);
}

void
scheme_main()
{
	char *argv[] = { "radiusd", NULL };
	scm_boot_guile (1, argv, scheme_boot, NULL);
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
	return RAD_SCM_EVAL((SCM)list);
}

static SCM
eval_catch_handler (void *data, SCM tag, SCM throw_args)
{
	scm_handle_by_message_noexit("radiusd", tag, throw_args);
	longjmp(*(jmp_buf*)data, 1);
}

int
scheme_try_auth(int auth_type, grad_request_t *req,
		grad_avp_t *user_check,
		grad_avp_t **user_reply_ptr)
{
	SCM s_request, s_check, s_reply;
	SCM res;
	SCM procsym;
 	jmp_buf jmp_env;
	grad_avp_t *tmp =
		radius_decrypt_request_pairs(req,
					     grad_avl_dup(req->request));
	static const char *try_auth = "radiusd-try-auth";
	
	s_request = radscm_avl_to_list(tmp);
	radius_destroy_pairs(&tmp);
	s_check = radscm_avl_to_list(user_check);
	s_reply = radscm_avl_to_list(*user_reply_ptr);

	/* Evaluate the procedure */
	procsym = RAD_SCM_SYMBOL_VALUE(try_auth);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		grad_log(L_ERR,
		         _("%s is not a procedure object"), try_auth);
		return 1;
	}
	if (setjmp(jmp_env)) {
		grad_log(L_NOTICE,
		         _("Procedure `%s' failed: see error output for details"),
		         try_auth);
		return 1;
	}
	res = scm_internal_lazy_catch(
		SCM_BOOL_T,
		eval_catch_body,
		(void*) SCM_LIST5(procsym,
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      scm_long2num(auth_type),
					      SCM_UNDEFINED),
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
		SCM code = SCM_CAR(res);
		grad_avp_t *list = radscm_list_to_avl(SCM_CDR(res));
		grad_avl_merge(user_reply_ptr, &list);
		grad_avl_free(list);
		return code == SCM_BOOL_F;
	}
	grad_log(L_ERR,
	         _("Unexpected return value from Guile authentication function `%s'"),
	         try_auth);
	return 1;
}

int
scheme_auth(char *procname, grad_request_t *req, 
	    grad_avp_t *user_check,
	    grad_avp_t **user_reply_ptr)
{
	SCM s_request, s_check, s_reply;
	SCM res;
	SCM procsym;
 	jmp_buf jmp_env;
	grad_avp_t *tmp =
		radius_decrypt_request_pairs(req,
					     grad_avl_dup(req->request));
	
	s_request = radscm_avl_to_list(tmp);
	radius_destroy_pairs(&tmp);
	s_check = radscm_avl_to_list(user_check);
	s_reply = radscm_avl_to_list(*user_reply_ptr);

	/* Evaluate the procedure */
	procsym = RAD_SCM_SYMBOL_VALUE(procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		grad_log(L_ERR,
		         _("%s is not a procedure object"), procname);
		return 1;
	}
	if (setjmp(jmp_env)) {
		grad_log(L_NOTICE,
		         _("Procedure `%s' failed: see error output for details"),
		         procname);
		return 1;
	}
	
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
		SCM code = SCM_CAR(res);
		grad_avp_t *list = radscm_list_to_avl(SCM_CDR(res));
		grad_avl_merge(user_reply_ptr, &list);
		grad_avl_free(list);
		return code == SCM_BOOL_F;
	}
	grad_log(L_ERR,
	         _("Unexpected return value from Guile authentication function `%s'"),
	         procname);
	return 1;
}

int
scheme_acct(char *procname, grad_request_t *req)
{
	SCM procsym, res;
	jmp_buf jmp_env;
	SCM s_request = radscm_avl_to_list(req->request);

	/* Evaluate the procedure */
	procsym = RAD_SCM_SYMBOL_VALUE(procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		grad_log(L_ERR,
		         _("%s is not a procedure object"), procname);
		return 1;
	}
	if (setjmp(jmp_env)) {
		grad_log(L_NOTICE,
		         _("Procedure `%s' failed: see error output for details"),
		         procname);
		return 1;
	}
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
	else
		grad_log(L_ERR,
		         _("Unexpected return value from Guile accounting function `%s'"),
		         procname);

	return 1;
}

void
scheme_add_load_path(char *path)
{
	rscm_add_load_path(path);
}

void
scheme_load(char *filename)
{
	scm_primitive_load_path(scm_makfrom0str(filename));
}

void
scheme_load_module(char *filename)
{
	scm_c_use_module(filename);
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
        SCM sym_top_repl = RAD_SCM_SYMBOL_VALUE("top-repl");
        SCM sym_begin = RAD_SCM_SYMBOL_VALUE("begin");

        list = scm_cons(sym_begin, scm_list_1(scm_cons(sym_top_repl, SCM_EOL)));
	status = scm_exit_status(RAD_SCM_EVAL_X(list));
        printf("%d\n", status);
}

static SCM
eval_close_port(void *port)
{
	scm_close_port((SCM)port);
	return SCM_BOOL_F;
}

void
silent_close_port(SCM port)
{
 	jmp_buf jmp_env;
	
	if (setjmp(jmp_env))
		return;
	scm_internal_lazy_catch(SCM_BOOL_T,
				eval_close_port, (void*)port,
				eval_catch_handler, &jmp_env);
}

void
scheme_redirect_output()
{
	SCM port;
	char *mode = "a";
	int fd = 2;

	if (scheme_outfile) {
		char *filename;

		if (scheme_outfile[0] == '/')
			filename = grad_estrdup(scheme_outfile);
		else
			filename = grad_mkfilename(radlog_dir ?
						   radlog_dir : RADLOG_DIR,
						   scheme_outfile);
		fd = open(filename, O_RDWR|O_CREAT|O_APPEND, 0600);
		if (fd == -1) {
			grad_log(L_ERR|L_PERROR,
			         _("can't open file `%s'"),
			         filename);
			fd = 2;
		}
		grad_free(filename);
	}

	port = scheme_error_port;
	scheme_error_port = scm_fdes_to_port(fd, mode,
					     scm_makfrom0str("<standard error>"));
	scm_set_current_output_port(scheme_error_port);
	scm_set_current_error_port(scheme_error_port);
	if (port != SCM_EOL) 
		silent_close_port(port);
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
scheme_cfg_load_module(int argc, cfg_value_t *argv, void *block_data,
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
	scheme_load_module(argv[1].v.string);
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

static int
scheme_cfg_outfile(int argc, cfg_value_t *argv,
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
	grad_free(scheme_outfile);
	scheme_outfile = grad_estrdup(argv[1].v.string);
	return 0;
}

struct cfg_stmt guile_stmt[] = {
	{ "load-path", CS_STMT, NULL, scheme_cfg_add_load_path, NULL, NULL, NULL },
	{ "load", CS_STMT, NULL, scheme_cfg_load, NULL, NULL, NULL },
	{ "load-module", CS_STMT, NULL, scheme_cfg_load_module, NULL, NULL, NULL },
	{ "debug", CS_STMT, NULL, scheme_cfg_debug, NULL, NULL, NULL },
	{ "outfile", CS_STMT, NULL, scheme_cfg_outfile, NULL, NULL, NULL },
	{ "gc-interval", CS_STMT, NULL, cfg_get_integer, &scheme_gc_interval,
	  NULL, NULL },
	{ NULL }
};

#else

int
scheme_try_auth(int auth_type, grad_request_t *req,
	    grad_avp_t *user_check,
	    grad_avp_t **user_reply_ptr)
{
	return 1;
}

#endif
