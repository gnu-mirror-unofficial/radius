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

#include <radiusd.h>
#include <libguile.h>
#include <setjmp.h>
#include <errno.h>

/* Protos to be moved to radscm */
SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);

/* Static declarations */
static void *guile_boot0(void *ignored);
static void guile_boot1(void *closure, int argc, char **argv);

struct call_data {
        struct call_data *next;
        pthread_cond_t cond;
        pthread_mutex_t mutex;
        int ready;
        int retval;
        int (*fun)(struct call_data*);
        char *procname;
        RADIUS_REQ *request;
        VALUE_PAIR *user_check;
        VALUE_PAIR **user_reply_ptr;
};

pthread_t guile_tid;
static pthread_mutex_t call_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t call_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
struct call_data *queue_head, *queue_tail;
static int scheme_inited;

void
call_place(cp)
        struct call_data *cp;
{
        pthread_mutex_lock(&queue_mutex);
        cp->next = NULL;
        if (!queue_head)
                queue_head = cp;
        else
                queue_tail->next = cp;
        queue_tail = cp;
        pthread_mutex_unlock(&queue_mutex);
}

void
call_remove(cp)
        struct call_data *cp;
{
        struct call_data *p, *prev = NULL;

        pthread_mutex_lock(&queue_mutex);
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
        pthread_mutex_unlock(&queue_mutex);
}

/* ************************************************************************* */
/* Boot up stuff */

void
start_guile()
{
        int rc;

        if (rc = pthread_create(&guile_tid, NULL, guile_boot0, NULL))
                radlog(L_ERR|L_PERROR, _("Can't spawn guile thread: %s"),
                       strerror(errno));
}

void *
guile_boot0(arg)
        void *arg;
{
        char *argv[] = { "radiusd", NULL };
        sigset_t sig;
        
        sigemptyset(&sig);
        pthread_sigmask(SIG_SETMASK, &sig, NULL);
        
        scm_boot_guile (1, argv, guile_boot1, arg);
        return NULL;
}       

static SCM
boot_body (void *data)
{
        struct call_data *p, *next;

        scm_init_load_path();
        radscm_init();
        rscm_radlog_init();
        rscm_rewrite_init();

        scheme_inited=1;
        pthread_mutex_lock(&call_mutex);

        while (1) {
		debug(1, ("SRV: Waiting"));
                pthread_cond_wait(&call_cond, &call_mutex);
                for (p = queue_head; p; ) {
                        next = p->next;
                        if (!p->ready) {
				debug(1, ("SRV: Handling request"));
                                p->retval = p->fun(p);
                                p->ready = 1;
                        }
			debug(1, ("SRV: Signalling"));
                        pthread_cond_signal(&p->cond);
                        p = next;
                }
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


void
scheme_add_load_path_internal(p)
        struct call_data *p;
{
        rscm_add_load_path(p->procname);
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
        int rc;
        struct timespec timeout;
    
        while (!scheme_inited)
                sleep(1);
        p->fun = fun;
        p->procname = procname;
        p->request = req;
        p->user_check = user_check;
        p->user_reply_ptr = user_reply_ptr;
        p->ready = 0;
        pthread_cond_init(&p->cond, NULL);
        pthread_mutex_init(&p->mutex, NULL);
        call_place(p);
	debug(1, ("APP: Placed call"));

        pthread_mutex_lock(&p->mutex);

        while (!p->ready) {
                struct timeval tv;
                gettimeofday(&tv, NULL);
                timeout.tv_sec = tv.tv_sec;
                timeout.tv_nsec = (tv.tv_usec + 1) * 1000;
                pthread_cond_signal(&call_cond);
                if (p->ready)
                        break;
                pthread_cond_timedwait(&p->cond, &p->mutex, &timeout);
        }
	debug(1, ("APP: Done"));
        
        pthread_mutex_unlock(&p->mutex);
        pthread_mutex_unlock(&call_mutex);
        call_remove(p);
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
scheme_read_eval_loop_internal()
{
        SCM list;
        int status;
        SCM sym_top_repl = scm_symbol_value0("top-repl");
        SCM sym_begin = scm_symbol_value0("begin");
        
        list = scm_cons(sym_begin, SCM_LIST1(scm_cons(sym_top_repl, SCM_EOL)));
        status = scm_exit_status(scm_eval_x(list));
        printf("%d\n", status);
}

void
scheme_read_eval_loop()
{
        scheme_generic_call(scheme_read_eval_loop_internal,
                            NULL, NULL, NULL, NULL);
}

void    
scheme_add_load_path(path)
{
        scheme_generic_call(scheme_add_load_path_internal,
                            path, NULL, NULL, NULL);
}

#endif
