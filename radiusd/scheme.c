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

#define RADIUS_MODULE_SCHEME_C

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

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

/* Implementation notes and a BIG FIXME:

   Current realisation of libguile (1.6) is not thread-safe in the
   sense that different threads cannot safely call scheme evaluation
   procedures. The problem is mainly in the garbage collector, which
   saves the address of the first automatic variable on the entry to
   scm_boot_guile_1 and then uses this address as the top of stack.
   Obviously, when the gc() gets called from another thread this address
   is not valid anymore and the thread sigfaults miserably.

   So, current workaround is to start a separate thread for processing
   scheme requests. This thread (let's call it scheme-server one) keeps
   a queue of tasks. Each thread wishing to execute a scheme procedure
   (a "client thread") first places it to the queue and then signals the
   scheme-server thread. Then the client thread waits until the server
   raises condition variable associated with the task, thereby signalling
   its completion.

   This creates an obvious buttleneck: assuming that the average time of
   execution of a scheme procedure is M seconds, the client will wait
   for the completion of its procedure at least M*(N+1) seconds, where
   N is the number of the requests in the queue by the time the thread
   places its task.

   This is hardly acceptable. To avoid possible thread cancellations
   a timeout is imposed on the execution of scheme requests. The timeout
   is REQUEST_TYPE_TTL/2 + 1. The value of the configuration variable
   `task-timeout' overrides this default, provided that

          task-timeout <= REQUEST_TYPE_TTL/2 + 1.

   Possibly, a better approach would be to set timeout to

          REQUEST_TYPE_TTL/N

   where N represents the number of scheme tasks waiting in the queue.

   Anyway, the solution of the bottleneck problem is badly needed. */
   
/* Protos to be moved to radscm */
SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);

/* Values for rad_scheme_task.state */
#define RSCM_TASK_WAITING 0
#define RSCM_TASK_READY   1
#define RSCM_TASK_DONE    2

struct rad_scheme_task;
typedef int (*scheme_task_fp)(struct rad_scheme_task*);

struct rad_scheme_task {
        struct rad_scheme_task *next;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        int state;
        int retval;
        scheme_task_fp fun;
        char *procname;
        RADIUS_REQ *request;
        VALUE_PAIR *user_check;
        VALUE_PAIR **user_reply_ptr;
};

/* Static declarations */
static void *guile_boot0(void *ignored);
static void guile_boot1(void *closure, int argc, char **argv);
static SCM boot_body(void *data);
static SCM boot_handler(void *data, SCM tag, SCM throw_args);
static SCM eval_catch_body(void *list);
static SCM eval_catch_handler(void *data, SCM tag, SCM throw_args); 

static int scheme_generic_call(int type,
                               scheme_task_fp fun,
			       char *procname, RADIUS_REQ *req,
			       VALUE_PAIR *user_check,
			       VALUE_PAIR **user_reply_ptr,
			       u_long timeout);
static void rad_scheme_place_task(struct rad_scheme_task *cp);
static void rad_scheme_remove_task(struct rad_scheme_task *cp);
static int scheme_auth_internal(struct rad_scheme_task *p);
static int scheme_acct_internal(struct rad_scheme_task *p);
static int scheme_before_config_internal(struct rad_scheme_task *p);
static int scheme_after_config_internal(struct rad_scheme_task *p);
static int scheme_load_internal(struct rad_scheme_task *p);
static int scheme_add_load_path_internal(struct rad_scheme_task *p);
static int scheme_read_eval_loop_internal(struct rad_scheme_task *unused);
static void scheme_before_config_hook(void *unused1, void *unused2);
static void scheme_after_config_hook(void *unused1, void *unused2);

/* variables */
pthread_t guile_tid;
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t server_cond = PTHREAD_COND_INITIALIZER;
struct rad_scheme_task *queue_head, *queue_tail;
static int scheme_inited;
unsigned scheme_gc_interval = 3600;
u_int scheme_task_timeout = 0;

void
rad_scheme_place_task(cp)
        struct rad_scheme_task *cp;
{
        cp->next = NULL;
        if (!queue_head)
                queue_head = cp;
        else
                queue_tail->next = cp;
        queue_tail = cp;
}

void
rad_scheme_remove_task(cp)
        struct rad_scheme_task *cp;
{
        struct rad_scheme_task *p, *prev = NULL;

        for (p = queue_head; p; ) {
                if (p == cp)
                        break;
                prev = p;
                p = p->next;
        }
        
        if (p) {
                if (prev)
                        prev->next = p->next;
                else
                        queue_head = p->next;
                if (p == queue_tail)
                        queue_tail = prev;
        }
}

/* ************************************************************************* */
/* Boot up stuff */

void
start_guile()
{
        int rc;

	register_before_config_hook(scheme_before_config_hook, NULL);
	register_after_config_hook(scheme_after_config_hook, NULL);
        if (rc = pthread_create(&guile_tid, NULL, guile_boot0, NULL))
                radlog(L_ERR, _("Can't spawn guile thread: %s"),
                       strerror(rc));
}

void *
guile_boot0(arg)
        void *arg;
{
        char *argv[] = { "radiusd", NULL };
        radiusd_thread_init();
        scm_boot_guile (1, argv, guile_boot1, arg);
        return NULL;
}       


/*ARGSUSED*/
static SCM
boot_body (void *data)
{
        time_t last_gc_time;
        
        scm_init_load_path();
        radscm_init();
        rscm_radlog_init();
        rscm_rewrite_init();

	
        time(&last_gc_time);
        scheme_inited = 1;
        
        Pthread_mutex_lock(&server_mutex);
        while (1) {
                struct rad_scheme_task *p;
                time_t t;

                if (time(&t) - last_gc_time > scheme_gc_interval) {
                        debug(1,("starting guile garbage collection"));
                        scm_gc();
                        debug(1,("finished guile garbage collection"));
                        last_gc_time = t;
                }
                
                debug(1, ("SRV: Waiting"));
                pthread_cond_wait(&server_cond, &server_mutex);
                
                debug(1, ("SRV: Processing queue"));
                p = queue_head;
		while (p) {
			struct rad_scheme_task *next = p->next;
			switch (p->state) {
			case RSCM_TASK_DONE:
				debug(1, ("SRV: Deleting completed task"));
				rad_scheme_remove_task(p);
				efree(p);
				break;

			case RSCM_TASK_WAITING:
                                debug(1, ("SRV: Handling request"));
                                p->retval = p->fun(p);
                                p->state = RSCM_TASK_READY;
				/*FALLTHROUGH*/

			case RSCM_TASK_READY:
			default:
				Pthread_mutex_lock(&p->mutex);
				pthread_cond_signal(&p->cond);
				Pthread_mutex_unlock(&p->mutex);
			}
			p = next;
                }
        }
        /*NOTREACHED*/
        return SCM_BOOL_F;
}

/*ARGSUSED*/
static SCM
boot_handler (void *data, SCM tag, SCM throw_args)
{
        return scm_handle_by_message_noexit("radiusd", tag, throw_args);
}

/*ARGSUSED*/
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
/* Functions running in Guile thread stack space */

static SCM
eval_catch_body (void *list)
{
        return scm_primitive_eval_x((SCM)list);
}

/*ARGSUSED*/
static SCM
eval_catch_handler (void *data, SCM tag, SCM throw_args)
{
        scm_handle_by_message_noexit("radiusd", tag, throw_args);
        longjmp(*(jmp_buf*)data, 1);
}

int
scheme_auth_internal(p)
        struct rad_scheme_task *p;
{
        SCM s_request, s_check, s_reply;
        SCM res;
        SCM procsym;
        jmp_buf jmp_env;
        
        s_request = radscm_avl_to_list(p->request->request);
        s_check = radscm_avl_to_list(p->user_check);
        s_reply = radscm_avl_to_list(*p->user_reply_ptr);

        /* Evaluate the procedure */
        procsym = RAD_SCM_SYMBOL_VALUE(p->procname);
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
                (void*) scm_list_4(procsym,
                                  scm_list_2(scm_copy_tree(SCM_IM_QUOTE),
                                             s_request),
                                  scm_list_2(scm_copy_tree(SCM_IM_QUOTE),
                                             s_check),
                                  scm_list_2(scm_copy_tree(SCM_IM_QUOTE),
                                             s_reply)),
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
        struct rad_scheme_task *p;
{
        SCM procsym, res;
        jmp_buf jmp_env;
        SCM s_request = radscm_avl_to_list(p->request->request);

        /* Evaluate the procedure */
        procsym = RAD_SCM_SYMBOL_VALUE(p->procname);
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
                (void*) scm_list_2(procsym,
                                  scm_list_2(SCM_IM_QUOTE,
                                             s_request)),
                eval_catch_handler, &jmp_env);
        if (SCM_IMP(res) && SCM_BOOLP(res)) 
                return res == SCM_BOOL_F;
        return 1;
}

/*ARGSUSED*/
int
scheme_before_config_internal(p)
	struct rad_scheme_task *p;
{
}

/*ARGSUSED*/
int
scheme_after_config_internal(p)
        struct rad_scheme_task *p;
{
	scm_gc();
	return 0;
}

int
scheme_load_internal(p)
        struct rad_scheme_task *p;
{
        scm_primitive_load_path(scm_makfrom0str(p->procname));
	return 0;
}


int
scheme_add_load_path_internal(p)
        struct rad_scheme_task *p;
{
        rscm_add_load_path(p->procname);
	return 0;
}

/*ARGSUSED*/
int
scheme_read_eval_loop_internal(unused)
	struct rad_scheme_task *unused;
{
        SCM list;
        int status;
        SCM sym_top_repl = RAD_SCM_SYMBOL_VALUE("top-repl");
        SCM sym_begin = RAD_SCM_SYMBOL_VALUE("begin");
        
        list = scm_cons(sym_begin, scm_list_1(scm_cons(sym_top_repl, SCM_EOL)));
        status = scm_exit_status(scm_primitive_eval_x(list));
        printf("%d\n", status);
	return 0;
}

/* ************************************************************************* */
/* Functions running in arbitrary stack space */

void
scheme_client_cleanup(arg)
	void *arg;
{
	struct rad_scheme_task *p = arg;
	
        Pthread_mutex_unlock(&p->mutex);
        pthread_mutex_destroy(&p->mutex);
        pthread_cond_destroy(&p->cond);
	p->state = RSCM_TASK_DONE;
}

int
scheme_generic_call(type, fun, procname, req, user_check, user_reply_ptr, timeout)
        int type;
        int (*fun)();
        char *procname;
        RADIUS_REQ *req;
        VALUE_PAIR *user_check;
        VALUE_PAIR **user_reply_ptr;
	u_long timeout;
{
	struct timespec atime;
	struct timeval now;
        struct rad_scheme_task *p = emalloc(sizeof(*p));
        int rc;
    
        while (!scheme_inited)
                sleep(1);
        p->fun = fun;
        p->procname = procname;
        p->request = req;
        p->user_check = user_check;
        p->user_reply_ptr = user_reply_ptr;
        p->state = RSCM_TASK_WAITING;
        pthread_cond_init(&p->cond, NULL);
        pthread_mutex_init(&p->mutex, NULL);
        
        if (radiusd_mutex_lock(&server_mutex, type) == 0) {
		rad_scheme_place_task(p);
		debug(1, ("APP: Placed call"));

		Pthread_mutex_lock(&p->mutex);

		debug(50, ("APP: Signalling"));
		pthread_cond_signal(&server_cond);
		radiusd_mutex_unlock(&server_mutex);

		pthread_cleanup_push(scheme_client_cleanup, p);

		gettimeofday(&now, NULL);
		atime.tv_sec = now.tv_sec + timeout;
		atime.tv_nsec = 0;
		
		while (p->state == RSCM_TASK_WAITING) {
			debug(50, ("APP: Waiting"));
			if (timeout) {
				if (pthread_cond_timedwait(&p->cond, &p->mutex, &atime)
				    == ETIMEDOUT)
					break;
			} else
				pthread_cond_wait(&p->cond, &p->mutex);
		}

		if (p->state == RSCM_TASK_WAITING) {
			radlog(L_NOTICE, "%s: %s",
		       		_("scheme task timed out"), procname);
		}
		rc = p->retval; /*FIXME*/
		pthread_cleanup_pop(1);
	}	
        
        return rc;
}

void
scheme_load(filename)
        char *filename;
{
        scheme_generic_call(R_AUTH, scheme_load_internal, filename,
			    NULL, NULL, NULL, 0);
}

void
scheme_before_config_hook(unused1, unused2)
	void *unused1;
	void *unused2;
{
        scheme_generic_call(R_AUTH, scheme_before_config_internal,
                            NULL, NULL, NULL, NULL, 0);
}

void
scheme_after_config_hook(unused1, unused2)
	void *unused1;
	void *unused2;
{
        scheme_generic_call(R_AUTH, scheme_after_config_internal,
                            NULL, NULL, NULL, NULL, 0);
}

u_long
scheme_compute_timeout(type)
	int type;
{
	u_long timeout = request_class[type].ttl/2 + 1;
	if (scheme_task_timeout && scheme_task_timeout < timeout)
		timeout = scheme_task_timeout;
	return timeout;
}

int
scheme_auth(procname, req, user_check, user_reply_ptr)
        char *procname;
        RADIUS_REQ *req;
        VALUE_PAIR *user_check;
        VALUE_PAIR **user_reply_ptr;
{
        return scheme_generic_call(R_AUTH,
                                   scheme_auth_internal,
                                   procname, req, user_check, user_reply_ptr,
				   scheme_compute_timeout(R_AUTH));
}

int
scheme_acct(procname, req)
        char *procname;
        RADIUS_REQ *req;
{
        return scheme_generic_call(R_ACCT,
                                   scheme_acct_internal,
                                   procname, req, NULL, NULL,
				   scheme_compute_timeout(R_ACCT));
}

void
scheme_read_eval_loop()
{
        scheme_generic_call(R_AUTH,
                            scheme_read_eval_loop_internal,
                            NULL, NULL, NULL, NULL, 0);
}

void    
scheme_add_load_path(path)
	char *path;
{
        scheme_generic_call(R_AUTH, scheme_add_load_path_internal,
                            path, NULL, NULL, NULL, 0);
}

/* ************************************************************************* */
/* Configuration issues */

int
guile_cfg_handler(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
{
	use_guile = 1;
	return 0;
}

static int
scheme_cfg_add_load_path(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
scheme_cfg_load(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
scheme_cfg_debug(argc, argv, block_data, handler_data)
	int argc;
	cfg_value_t *argv;
	void *block_data;
	void *handler_data;
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
