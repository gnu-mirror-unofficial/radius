/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

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

#if defined(HAVE_CONFIG_H)        
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <common.h>
#include <radius/radargp.h>
#include <radtest.h>
#include <radius/argcv.h>

grad_symtab_t *vartab;
int verbose;
extern int grad_client_debug;
grad_server_queue_t *srv_queue;
int reply_code;
grad_avp_t *reply_list;
int abort_on_failure = 0;

void init_symbols();
static void assign(char *);

int x_argmax;
int x_argc;
char **x_argv;

int quick = 0;
char *filename = NULL;
char *server = NULL;
int retry = 0;
int timeout = 0;
int disable_readline;

const char *argp_program_version = "radtest (" PACKAGE ") " VERSION;
static char doc[] = N_("send arbitrary radius packets");

static struct argp_option options[] = {
        {NULL, 0, NULL, 0,
         N_("radtest specific switches:"), 0},
        {"assign", 'a', N_("VARIABLE=VALUE"), 0,
         N_("assign a VALUE to VARIABLE"), 0},
        {"debug", 'x', "DEBUGSPEC", 0,
         N_("set debugging level"), 0},
        {"file", 'f', N_("FILE"), 0,
         N_("Read input from FILE. When this option is used, all unknown"
         " options in the form --VAR=VALUE are treated as variable"
         " assignments"), 0},
        {"quick", 'q', NULL, 0,
         "FIXME: quick mode", 0},
        {"retry", 'r', N_("NUMBER"), 0,
         N_("set number of retries"), 0},
        {"server", 's', N_("SERVER"), 0,
         N_("set radius server parameters"), 0},
        {"timeout", 't', N_("NUMBER"), 0,
         N_("set timeout"), 0},
        {"verbose", 'v', NULL, 0,
         N_("verbose mode"), 0},
	{"no-interactive", 'n', NULL, 0,
	 N_("disable interactive mode"), 0 },
        {NULL, 0, NULL, 0, NULL, 0}
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'a':
                assign(optarg);
                break;
		
        case 'q':
                quick++;
                break;
		
        case 'r':
                retry = strtol(optarg, NULL, 0);
                break;
		
        case 's':
                server = optarg;
                break;
		
        case 'f':
                filename = optarg;
                break;

	case 'n':
		disable_readline = 1;
		break;
		
        case 't':
                timeout = strtol(optarg, NULL, 0);
                break;
		
        case 'x':
                set_debug_levels(optarg);
                break;
		
        case 'v':
                verbose++;
		set_module_debug_level("radpdu", 100);
		set_module_debug_level("client", 100);
                break;

        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static struct argp argp = {
        options,
        parse_opt,
        NULL,
        doc,
        rad_common_argp_child,
        NULL, NULL
};

int
main(int argc, char **argv)
{
        char *p;
        int index;
	radtest_variable_t *var;
	
        grad_app_setup();
        init_symbols();

        index = argc;
        if (grad_argp_parse(&argp, &argc, &argv, 0, &index, NULL))
                return 1;

        argv += index;
        argc -= index;

        set_yydebug();
        grad_path_init();
	srand(time(NULL));
	
        if (grad_dict_init()) {
                grad_log(L_ERR, _("error reading dictionary file"));
                return 1;
        }
        srv_queue = grad_client_create_queue(!quick, 0, 0);
        
        if (!srv_queue)
                return 1;

	var = (radtest_variable_t*)grad_sym_lookup(vartab, "SOURCEIP");
	var->datum.ipaddr = srv_queue->source_ip;
		
	if (timeout)
                srv_queue->timeout = timeout;
        if (retry)
                srv_queue->retries = retry;
        if (server) {
                grad_server_t serv;
                int i, argc;
                char **argv;

                if (argcv_get(server, ":", NULL, &argc, &argv)) {
                        grad_log(L_ERR, _("can't parse server definition"));
                        exit(1);
                }

                if (argc < 3) {
                        grad_log(L_ERR, _("no shared secret for the server"));
                        exit(1);
                }

                memset(&serv, 0, sizeof serv);
                serv.name = "default";
                for (i = 0; i < argc; i++) {
                        switch (i) {
                        case 0:
                                serv.addr = grad_ip_gethostaddr(argv[i]);
                                if (!serv.addr) {
                                        grad_log(L_ERR,
                                                 _("bad IP address or host name: %s"),
                                                 argv[i]);
                                        exit(1);
                                }
                                break;
                        case 2:
                                serv.secret = argv[i];
                                break;
                        case 4:
                                serv.port[0] = strtol(argv[i], &p, 0);
                                if (*p) {
                                        grad_log(L_ERR,
                                                 _("bad port number %s"),
                                                 argv[i]);
                                        break;
                                }
                                break;
                        case 6:
                                serv.port[1] = strtol(argv[i], &p, 0);
                                if (*p) {
                                        grad_log(L_ERR,
                                                 _("bad port number %s"),
                                                 argv[i]);
                                        break;
                                }
                                break;
                        default:
                                if (argv[i][0] != ':') {
                                        grad_log(L_ERR,
                                                 _("bad separator near %s"),
                                                 argv[i]);
                                        exit(1);
                                }
                                break;
                        }
                }

                if (argc < 4)
                        serv.port[0] = DEF_AUTH_PORT;
                if (argc < 6)
                        serv.port[1] = DEF_ACCT_PORT;
		grad_client_append_server(srv_queue,
					  grad_client_alloc_server(&serv));
                argcv_free(argc, argv);
        }

        if (grad_list_count(srv_queue->servers) == 0) {
                grad_log(L_ERR,
                         _("No servers specfied. Use -s option.\n"));
                exit(1);
        }
        
        x_argmax = argc + 2;
        x_argv = grad_emalloc(sizeof(x_argv[0]) * x_argmax);
        x_argc = 0;
        x_argv[x_argc++] = filename;

        for (; argc; argv++, argc--) {
                if (argv[0][0] == '-'
                    && argv[0][1] == '-'
                    && (p = strchr(argv[0], '=')) != NULL
                    && !(p > argv[0] && p[-1] == '\\')) 
                        assign(argv[0]+2);
                else if ((p = strchr(*argv, '=')) != NULL &&
                         !(p > *argv && p[-1] == '\\')) 
                        assign(*argv);
                else 
                        x_argv[x_argc++] = *argv;
        }
        x_argv[x_argc++] = NULL;
        
        if (open_input(filename))
                return 1;
        return yyparse();
}

void
init_symbols()
{
        radtest_variable_t *var;
        
        vartab = grad_symtab_create(sizeof(radtest_variable_t), NULL);
        var = (radtest_variable_t*) grad_sym_install(vartab, "REPLY_CODE");
        var->type = rtv_integer;
        var = (radtest_variable_t*) grad_sym_install(vartab, "REPLY");
        var->type = rtv_avl;
	var = (radtest_variable_t*) grad_sym_install(vartab, "SOURCEIP");
	var->type = rtv_ipaddress;
}

void
assign(char *s)
{
        char *p;
        radtest_variable_t *var;
        radtest_datum_t datum;
        radtest_data_type type = rtv_undefined;
        
        p = strchr(s, '=');
        if (!p) {
                fprintf(stderr, _("assign: expected `='\n"));
                return;
        }
        *p++ = 0;

        type = parse_datum(p, &datum);
        if (type == rtv_undefined)
                return;
        var = (radtest_variable_t*)grad_sym_install(vartab, s);
        var->type = type;
        var->datum = datum;
}

radtest_data_type
parse_datum(char *p, radtest_datum_t *dp)
{
        radtest_data_type type = rtv_undefined;
        int length;
        
        if (*p == '"') {
                length = strlen(++p);
                if (length == 0 || p[length-1] != '"') {
                        fprintf(stderr, _("assign: missing closing quote\n"));
                        return rtv_undefined;
                }
                p[length-1] = 0;
                
                type = rtv_string;
                dp->string = grad_estrdup(p);
        } else if (isdigit(*p)) {
                char *endp;
                
                /* This can be either an integer or an IP address */
                dp->number = strtol(p, &endp, 0);
                if (*endp == 0) {
                        type = rtv_integer;
                } else {
                        /* IP address */
                        if ((dp->ipaddr = grad_ip_gethostaddr(p)) != 0)
                                type = rtv_ipaddress;
                        else {
                                fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
                                return rtv_undefined;
                        }
                } 
        } else if (strchr(p, '.')) {
                /* IP address */
                if ((dp->ipaddr = grad_ip_gethostaddr(p)) != 0)
                        type = rtv_ipaddress;
                else {
                        fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
                        return rtv_undefined;
                }
        } else {
                type = rtv_string;
                dp->string = grad_estrdup(p);
        }
        return type;
}

void
print_pairs(FILE *fp, grad_avp_t *pair)
{
        for (; pair; pair = pair->next) {
		char *save;
		fprintf(fp, " %s", grad_format_pair(pair, 1, &save));
		free(save);
                if (pair->next)
                        fprintf(fp, ",");
                else
                        fprintf(fp, " ");
/*              fprintf(fp, "\n");*/
        }
}

void
var_print(radtest_variable_t *var)
{
        char buf[DOTTED_QUAD_LEN];
        if (!var)
                return;
        switch (var->type) {
        case rtv_undefined:
                printf("UNDEFINED");
                break;
		
        case rtv_integer:
                printf("%d", var->datum.number);
                break;
		
        case rtv_ipaddress:
                printf("%s", grad_ip_iptostr(var->datum.ipaddr, buf));
                break;
		
        case rtv_string:
                printf("%s", var->datum.string);
                break;
		
        case rtv_avl:
                printf("(");
                print_pairs(stdout, var->datum.avl);
                printf(")");
                break;
        }
}

int
var_free(radtest_variable_t *var)
{
        switch (var->type) {
        case rtv_string:
                grad_free(var->datum.string);
                break;
        case rtv_avl:
                grad_avl_free(var->datum.avl);
                break;
        }
}

void
radtest_send(int port, int code, grad_avp_t *avl, grad_symtab_t *cntl)
{
        grad_request_t *auth;
	radtest_variable_t *p;
	
        if (reply_list)
                grad_avl_free(reply_list);
        reply_list = NULL;
        reply_code = 0;
        
	if (!cntl) {
		auth = grad_client_send(srv_queue, port, code, avl);
	} else {
		int id;
		u_char vector[AUTH_VECTOR_LEN];
		int sflags = 0;
		int retry = 1;
		radtest_variable_t *delay = (radtest_variable_t*)grad_sym_lookup(cntl, "delay");
		
		p = (radtest_variable_t*)grad_sym_lookup(cntl, "repeat");
		if (p)
			retry = p->datum.number;
		p = (radtest_variable_t*)grad_sym_lookup(cntl, "id");
		if (p) {
			sflags |= RADCLT_ID;
			id = p->datum.number;
		}
		p = (radtest_variable_t*)grad_sym_lookup(cntl, "keepauth");
		if (p && p->datum.number) 
			sflags |= RADCLT_AUTHENTICATOR;
		auth = grad_client_send0(srv_queue,
					 port,
					 code,
					 avl,
					 0,
					 &id,
					 vector);
		while (--retry) {
			if (delay)
				sleep(delay->datum.number);
			auth = grad_client_send0(srv_queue,
						 port,
						 code,
						 avl,
						 sflags,
						 &id,
						 vector);
		}
	}

	if (!auth)
		return;
        reply_code = auth->code;
        p = (radtest_variable_t*)grad_sym_lookup(vartab, "REPLY_CODE");
        p->type = rtv_integer;
        p->datum.number = reply_code;

        reply_list = grad_client_decrypt_pairlist(grad_avl_dup(auth->request),
						  auth->vector, auth->secret);

        p = (radtest_variable_t*)grad_sym_lookup(vartab, "REPLY");
        p->type = rtv_avl;
        p->datum.avl = reply_list;
        grad_request_free(auth);
}

/* FIXME: duplicated in radiusd/files.c */
int
comp_op(enum grad_operator op, int result)
{
        switch (op) {
        default:
        case grad_operator_equal:
                if (result != 0)
                        return -1;
                break;

        case grad_operator_not_equal:
                if (result == 0)
                        return -1;
                break;

        case grad_operator_less_than:
                if (result >= 0)
                        return -1;
                break;

        case grad_operator_greater_than:
                if (result <= 0)
                        return -1;
                break;
                    
        case grad_operator_less_equal:
                if (result > 0)
                        return -1;
                break;
                        
        case grad_operator_greater_equal:
                if (result < 0)
                        return -1;
                break;
        }
        return 0;
}

int
compare_lists(grad_avp_t *reply, grad_avp_t *sample)
{
        int result = 0;
        
        for (; sample && result == 0; sample = sample->next) {
                grad_avp_t *p;

                if (sample->attribute > 255)
                        continue;
                for (p = reply; p && p->attribute != sample->attribute;
                     p = p->next)
                        ;
                if (!p)
                        return -1;
                switch (p->type) {
                case TYPE_STRING:
                        result = strcmp(sample->avp_strvalue, p->avp_strvalue);
                        break;
                case TYPE_INTEGER:
                case TYPE_IPADDR:
                        result = sample->avp_lvalue - p->avp_lvalue;
                        break;
                default:
                        result = -1;
                }
                result = comp_op(sample->operator, result);
        }
        return result;
}

