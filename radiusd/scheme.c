/* This file is part of GNU Radius.
   Copyright (C) 2001,2002,2003,2004,2005,2007,
   2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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

#include <unistd.h>
#include <fcntl.h>
#include <radiusd.h>
#include <setjmp.h>
#include <errno.h>

#ifdef USE_SERVER_GUILE
#include <libguile.h>
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

static void scheme_before_config_hook(void *a, void *b);


/* General-purpose eval handlers */

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


/* Configuration handlers and auxiliary functions */

static void
scheme_debug(int val)
{
	SCM_DEVAL_P = val;
	SCM_BACKTRACE_P = val;
	SCM_RECORD_POSITIONS_P = val;
	SCM_RESET_DEBUG_MODE;
}
		
static void
scheme_add_load_path(char *path)
{
	rscm_add_load_path(path);
}

struct scheme_exec_data {
	SCM (*handler) (void *data);
	void *data;
	SCM result;
};

static SCM
scheme_safe_exec_body (void *data)
{
	struct scheme_exec_data *ed = data;
	ed->result = ed->handler (ed->data);
	return SCM_BOOL_F;
}

static int
scheme_safe_exec(SCM (*handler) (void *data), void *data, SCM *result)
{
 	jmp_buf jmp_env;
	struct scheme_exec_data ed;
	
	if (setjmp(jmp_env))
		return 1;
	ed.handler = handler;
	ed.data = data;
	scm_internal_lazy_catch(SCM_BOOL_T,
				scheme_safe_exec_body, (void*)&ed,
				eval_catch_handler, &jmp_env);
	if (result)
		*result = ed.result;
	return 0;
}

static SCM
load_path_handler(void *data)
{
	scm_primitive_load_path((SCM)data);
	return SCM_UNDEFINED;
}

static int
scheme_load(char *filename)
{
	return scheme_safe_exec(load_path_handler, scm_makfrom0str(filename),
				NULL);
}

static SCM
load_module_handler(void *data)
{
	scm_c_use_module(data);
	return SCM_UNDEFINED;
}

static int
scheme_load_module(char *filename)
{
	return scheme_safe_exec(load_module_handler, filename, NULL);
}

static SCM
eval_expr(void *data)
{
	return scm_eval_string((SCM)data);
}

static int
scheme_eval_expression(char *exp, SCM *result)
{
	return scheme_safe_exec(eval_expr, scm_makfrom0str(exp), result);
}

static void
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
close_port_handler(void *port)
{
	scm_close_port((SCM)port);
	return SCM_UNDEFINED;
}

static void
silent_close_port(SCM port)
{
	scheme_safe_exec(close_port_handler, port, NULL);
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
			filename = grad_mkfilename(grad_log_dir ?
						   grad_log_dir : RADLOG_DIR,
						   scheme_outfile);
		fd = open(filename, O_RDWR|O_CREAT|O_APPEND, 0600);
		if (fd == -1) {
			grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR,
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

int
scheme_call_proc(SCM *result, char *procname, SCM arglist)
{
	SCM procsym;
 	jmp_buf jmp_env;
	SCM cell;
	
	/* Evaluate the procedure */
	procsym = RAD_SCM_SYMBOL_VALUE(procname);
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		grad_log(GRAD_LOG_ERR,
		         _("%s is not a procedure object"), procname);
		return 1;
	}
	if (setjmp(jmp_env)) {
		grad_log(GRAD_LOG_NOTICE,
		         _("Procedure `%s' failed: see error output for details"),
		         procname);
		return 1;
	}
	cell = scm_cons(procsym, arglist);
	*result = scm_internal_lazy_catch(SCM_BOOL_T,
					  eval_catch_body, cell,
					  eval_catch_handler, &jmp_env);
	return 0;
}

void
scheme_eval_unspecified_expr(char *expr)
{
	scheme_eval_expression(expr, NULL);
}

int
scheme_eval_boolean_expr(char *expr)
{
	SCM result;
	if (scheme_eval_expression(expr, &result))
		return -1;
	return result != SCM_BOOL_F;
}


/* Main loop */

static SCM
catch_body(void *data)
{
        SCM orig_load_path;
         
        scheme_redirect_output();
	scm_init_load_path();
	grad_scm_init();
	orig_load_path = RAD_SCM_SYMBOL_VALUE("%load-path");
	radiusd_set_preconfig_hook(scheme_before_config_hook, orig_load_path,
				   0);
	rscm_server_init();
	scheme_load_module("radiusd");
	radiusd_main();
	return SCM_BOOL_F;
}

static SCM
catch_handler(void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}


static void
scheme_before_config_hook(void *data, void *b ARG_UNUSED)
{
	SCM *pscm;
	pscm = SCM_VARIABLE_LOC(scm_c_lookup("%load-path"));
	*pscm = (SCM) data;
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


/* Entry points for main Radius tasks */

int
scheme_try_auth(int auth_type, radiusd_request_t *req,
		grad_avp_t *user_check,
		grad_avp_t **user_reply_ptr)
{
	SCM s_request, s_check, s_reply;
	SCM res;
	grad_avp_t *tmp =
		radius_decrypt_request_pairs(req,
					     grad_avl_dup(req->request->avlist));
        static char *try_auth = "radiusd-try-auth";
	
	s_request = radscm_avl_to_list(tmp);
	radius_destroy_pairs(&tmp);
	s_check = radscm_avl_to_list(user_check);
	s_reply = radscm_avl_to_list(*user_reply_ptr);

	if (scheme_call_proc(&res,
			     try_auth,
			     scm_list_4(scm_cons(SCM_IM_QUOTE, auth_type),
					scm_cons(SCM_IM_QUOTE, s_request),
					scm_cons(SCM_IM_QUOTE, s_check),
					scm_cons(SCM_IM_QUOTE, s_reply))))
		return 1;
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	if (SCM_NIMP(res) && SCM_CONSP(res)) {
		SCM code = SCM_CAR(res);
		grad_avp_t *list = radscm_list_to_avl(SCM_CDR(res));
		grad_avl_merge(user_reply_ptr, &list);
		grad_avl_free(list);
		return code == SCM_BOOL_F;
	}
	grad_log(GRAD_LOG_ERR,
	         _("Unexpected return value from Guile authentication function `%s'"),
	         try_auth);
	return 1;
}

int
scheme_auth(char *procname, radiusd_request_t *req, 
	    grad_avp_t *user_check,
	    grad_avp_t **user_reply_ptr)
{
	SCM s_request, s_check, s_reply;
	SCM res;
	grad_avp_t *tmp =
		radius_decrypt_request_pairs(req,
					     grad_avl_dup(req->request->avlist));
	
	s_request = radscm_avl_to_list(tmp);
	radius_destroy_pairs(&tmp);
	s_check = radscm_avl_to_list(user_check);
	s_reply = radscm_avl_to_list(*user_reply_ptr);

	if (scheme_call_proc(&res,
			     procname,
			     scm_list_3(scm_cons(SCM_IM_QUOTE, s_request),
					scm_cons(SCM_IM_QUOTE, s_check),
					scm_cons(SCM_IM_QUOTE, s_reply))))
		return 1;
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	if (SCM_NIMP(res) && SCM_CONSP(res)) {
		SCM code = SCM_CAR(res);
		grad_avp_t *list = radscm_list_to_avl(SCM_CDR(res));
		grad_avl_merge(user_reply_ptr, &list);
		grad_avl_free(list);
		return code == SCM_BOOL_F;
	}
	grad_log(GRAD_LOG_ERR,
	         _("Unexpected return value from Guile authentication function `%s'"),
	         procname);
	return 1;
}

int
scheme_acct(char *procname, radiusd_request_t *req)
{
	SCM res;
	SCM s_request = radscm_avl_to_list(req->request->avlist);

	if (scheme_call_proc(&res,
			     procname,
			     scm_list_1(scm_cons(SCM_IM_QUOTE, s_request))))
		return 1;
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) 
		return res == SCM_BOOL_F;
	else
		grad_log(GRAD_LOG_ERR,
		         _("Unexpected return value from Guile accounting function `%s'"),
		         procname);

	return 1;
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

static SCM
arglist_to_scm(int argc, cfg_value_t *argv)
{
        SCM head = SCM_EOL,
		tail; /* Don't let gcc fool you: tail cannot be used
			 uninitialized */
	SCM val;
	int i;
	unsigned long num;
	
	for (i = 1; i < argc; i++) {
                SCM cell;

		switch (argv[i].type) {
		case CFG_INTEGER:
			val = scm_from_long(argv[i].v.number);
			break;
			
		case CFG_BOOLEAN:
			val = argv[i].v.bool ? SCM_BOOL_T : SCM_BOOL_F;
			break;
			
		case CFG_STRING:
		{
			char *p = argv[i].v.string;
			if (p[0] == '#') {
				switch (p[1]) {
				case ':':
					val = scm_c_make_keyword(p + 2);
					break;
				case 'f':
					val = SCM_BOOL_F;
					break;

				case 't':
					val = SCM_BOOL_T;
					break;
				case 'x':
					num = strtoul(p+1, &p, 16);
					if (*p) {
						grad_log(GRAD_LOG_ERR,
							 _("Invalid hex number: %s"),
							 argv[i].v.string);
						return SCM_BOOL_F;
					}
					val = scm_from_long(num);
				default:
					val = scm_makfrom0str(p);
				}
			} else if (p[0] == '-') 
				val = scm_c_make_keyword(p + 1);
			else
				val = scm_makfrom0str(p);
		}
		break;

		case CFG_NETWORK:
			val = scm_cons(scm_from_ulong(argv[i].v.network.ipaddr),
			               scm_from_ulong(argv[i].v.network.netmask));
			break;
			
		case CFG_IPADDR:
		case CFG_PORT:
			grad_insist_fail("Such CFG_ value should never be returned");
			break;
			
		case CFG_CHAR:
			val = SCM_MAKE_CHAR(argv[i].v.ch);
			break;
			
		case CFG_HOST:
			val = scm_cons(scm_from_long(argv[i].v.host.ipaddr),
			               scm_from_long(argv[i].v.host.port));
		}

		cell = scm_cons(scm_cons(SCM_IM_QUOTE, val), SCM_EOL);

		if (head == SCM_EOL)
			head = cell;
		else
			SCM_SETCDR(tail, cell);
		tail = cell;
	}

	if (head != SCM_EOL)
		SCM_SETCDR(tail, SCM_EOL);
	return head;
}

#define INIT_SUFFIX "-init"
static void
call_module_init(const char *modname, SCM arglist)
{
	char *p = grad_emalloc(strlen(modname) + sizeof(INIT_SUFFIX));
	SCM res;
	
	strcat(strcpy(p, modname), INIT_SUFFIX);
	scheme_call_proc(&res, p, arglist);
	grad_free(p);
}

static int
scheme_cfg_load_module(int argc, cfg_value_t *argv, void *block_data,
		       void *handler_data)
{
	if (argc < 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	
	if (scheme_load_module(argv[1].v.string) == 0) {
		if (argc > 2) {
			SCM arglist = arglist_to_scm(argc - 1, argv + 1);
			call_module_init(argv[1].v.string, arglist);
		}	
	}
	return 0;
}

static int
scheme_cfg_eval(int argc, cfg_value_t *argv, void *block_data,
		void *handler_data)
{
	int i;

	if (argc < 2) {
		cfg_argc_error(0);
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (argv[i].type != CFG_STRING)
			cfg_type_error(CFG_STRING);
		else
			scheme_eval_expression(argv[i].v.string, NULL);
	}
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
	{ "eval", CS_STMT, NULL, scheme_cfg_eval, NULL, NULL, NULL },
	{ "debug", CS_STMT, NULL, scheme_cfg_debug, NULL, NULL, NULL },
	{ "outfile", CS_STMT, NULL, scheme_cfg_outfile, NULL, NULL, NULL },
	{ "gc-interval", CS_STMT, NULL, cfg_get_unsigned, &scheme_gc_interval,
	  NULL, NULL },
	{ NULL }
};

#else

#include <radius/radius.h>

int
scheme_try_auth(int auth_type, radiusd_request_t *req,
	        grad_avp_t *user_check,
	        grad_avp_t **user_reply_ptr)
{
	return 1;
}

void
scheme_eval_unspecified_expr(char *expr)
{
}

int
scheme_eval_boolean_expr(char *expr)
{
	return -1;
}

#endif

int
scheme_eval_avl (radiusd_request_t *request,
		 grad_avp_t *lhs, grad_avp_t *rhs,
		 grad_avp_t **reply,
		 grad_avp_t **pfailed)
{
#ifdef USE_SERVER_GUILE
	int rc = 0;
        grad_avp_t *p;
        
        if (!use_guile) {
                grad_log_req(GRAD_LOG_ERR, request->request,
                             _("Guile authentication disabled in config"));
                return -1;
        }

	for (p = rhs; p; p = p->next) {
		if (p->attribute == DA_SCHEME_PROCEDURE) {
			rc = scheme_auth(p->avp_strvalue, request, lhs,
					 reply); 
			if (rc) {
				if (pfailed)
					*pfailed = p;
				break;
			}
                }
        }

	return rc;
#else
        grad_log_req(GRAD_LOG_ERR, request->request,
                     _("Guile authentication not available"));
        return -1;
#endif
}
