/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003, Sergey Poznyakoff
 
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

#include <radius.h>
#include <radargp.h>
#include <radtest.h>
#include <argcv.h>

Symtab *vartab;
int verbose;
extern int rad_clt_debug;
RADIUS_SERVER_QUEUE *srv_queue;
char *progname;
int reply_code;
VALUE_PAIR *reply_list;
int debug_flag = 0;
int abort_on_failure = 0;

void init_symbols();
static void assign(char *);
int parse_datum(char *p, union datum *dp);

int x_argmax;
int x_argc;
char **x_argv;

int quick = 0;
char *filename = NULL;
char *server = NULL;
int retry = 0;
int timeout = 0;

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
                *(int *)state->input = state->next;
                state->next = state->argc;
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
        
        app_setup();
        initlog(argv[0]);
        init_symbols();

        index = argc;
        if (rad_argp_parse(&argp, &argc, &argv, 0, NULL, &index))
                return 1;

        argv += index;
        argc -= index;

        set_yydebug();
        radpath_init();
        if (dict_init()) {
                radlog(L_ERR, _("error reading dictionary file"));
                return 1;
        }
        srv_queue = rad_clt_create_queue(!quick, 0, 0);
        
        if (!srv_queue)
                return 1;

        if (timeout)
                srv_queue->timeout = timeout;
        if (retry)
                srv_queue->retries = retry;
        if (server) {
                RADIUS_SERVER serv;
                int i, argc;
                char **argv;

                if (argcv_get(server, ":", &argc, &argv)) {
                        radlog(L_ERR, "can't parse server definition");
                        exit(1);
                }

                if (argc < 3) {
                        radlog(L_ERR, "no shared secret for the server");
                        exit(1);
                }

                memset(&serv, 0, sizeof serv);
                serv.name = "default";
                for (i = 0; i < argc; i++) {
                        switch (i) {
                        case 0:
                                serv.addr = ip_gethostaddr(argv[i]);
                                if (!serv.addr) {
                                        radlog(L_ERR,
                                             "bad IP address or host name: %s",
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
                                        radlog(L_ERR,
                                               "bad port number %s",
                                               argv[i]);
                                        break;
                                }
                                break;
                        case 6:
                                serv.port[1] = strtol(argv[i], &p, 0);
                                if (*p) {
                                        radlog(L_ERR,
                                               "bad port number %s",
                                               argv[i]);
                                        break;
                                }
                                break;
                        default:
                                if (argv[i][0] != ':') {
                                        radlog(L_ERR,
                                               "bad separator near %s",
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
		rad_clt_append_server(srv_queue, rad_clt_alloc_server(&serv));
                argcv_free(argc, argv);
        }

        if (list_count(srv_queue->servers) == 0) {
                radlog(L_ERR,
                       "No servers specfied. Use -s option.\n");
                exit(1);
        }
        
        x_argmax = argc + 2;
        x_argv = emalloc(sizeof(x_argv[0]) * x_argmax);
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
        Variable *var;
        
        vartab = symtab_create(sizeof(Variable), NULL);
        var = (Variable*) sym_install(vartab, "REPLY_CODE");
        var->type = Integer;
        var = (Variable*) sym_install(vartab, "REPLY");
        var->type = Vector;
}

void
assign(char *s)
{
        char *p;
        Variable *var;
        union datum datum;
        int type = Undefined;
        
        p = strchr(s, '=');
        if (!p) {
                fprintf(stderr, _("assign: expected `='\n"));
                return;
        }
        *p++ = 0;

        type = parse_datum(p, &datum);
        if (type == Undefined)
                return;
        var = (Variable*)sym_install(vartab, s);
        var->type = type;
        var->datum = datum;
}

int
parse_datum(char *p, union datum *dp)
{
        int type = Undefined;
        int length;
        
        if (*p == '"') {
                length = strlen(++p);
                if (length == 0 || p[length-1] != '"') {
                        fprintf(stderr, _("assign: missing closing quote\n"));
                        return Undefined;
                }
                p[length-1] = 0;
                
                type = String;
                dp->string = estrdup(p);
        } else if (isdigit(*p)) {
                char *endp;
                
                /* This can be either an integer or an IP address */
                dp->number = strtol(p, &endp, 0);
                if (*endp == 0) {
                        type = Integer;
                } else {
                        /* IP address */
                        if ((dp->ipaddr = ip_gethostaddr(p)) != 0)
                                type = Ipaddress;
                        else {
                                fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
                                return Undefined;
                        }
                } 
        } else if (strchr(p, '.')) {
                /* IP address */
                if ((dp->ipaddr = ip_gethostaddr(p)) != 0)
                        type = Ipaddress;
                else {
                        fprintf(stderr, _("assign: invalid IP address: %s\n"), p);
                        return Undefined;
                }
        } else {
                type = String;
                dp->string = estrdup(p);
        }
        return type;
}

char *
print_ident(Variable *var)
{
        char buf[64];
        switch (var->type) {
        case Undefined:
                return estrdup("UNDEFINED");
                break;
        case Integer:
                sprintf(buf, "%d", var->datum.number);
                return estrdup(buf);
        case Ipaddress:
                ip_iptostr(var->datum.ipaddr, buf);
                return estrdup(buf);
        case String:
                return estrdup(var->datum.string);
                break;
        case Vector:
                return estrdup("VECTOR");
        }
	return NULL;
}

void
print_pairs(FILE *fp, VALUE_PAIR *pair)
{
        for (; pair; pair = pair->next) {
                fprintf(fp, " %s = ", pair->name);
                switch (pair->type) {
                case TYPE_STRING:
                        fprintf(fp, "(STRING) %s", pair->avp_strvalue);
                        break;

                case TYPE_INTEGER:
                        fprintf(fp, "(INTEGER) %ld", pair->avp_lvalue);
                        break;

                case TYPE_IPADDR:
                        fprintf(fp, "(IP) %lx", pair->avp_lvalue);
                        break;
                
                case TYPE_DATE:
                        fprintf(fp, "(DATE) %ld", pair->avp_lvalue);
                        break;
                        
                default:
                        fprintf(fp, "(%d)", pair->type);
                }
                if (pair->next)
                        fprintf(fp, ",");
                else
                        fprintf(fp, " ");
/*              fprintf(fp, "\n");*/
        }
}

void
var_print(Variable *var)
{
        char buf[DOTTED_QUAD_LEN];
        if (!var)
                return;
        switch (var->type) {
        case Undefined:
                printf("UNDEFINED");
                break;
        case Integer:
                printf("%d", var->datum.number);
                break;
        case Ipaddress:
                printf("%s", ip_iptostr(var->datum.ipaddr, buf));
                break;
        case String:
                printf("%s", var->datum.string);
                break;
        case Vector:
                printf("{");
                print_pairs(stdout, var->datum.vector);
                printf("}");
                break;
        case Builtin:
                var->datum.builtin.print();
                break;
        }
}

void
var_free(Variable *var)
{
        if (var->name)
                return; /* named variables are not freed */
        switch (var->type) {
        case String:
                efree(var->datum.string);
                break;
        case Vector:
                avl_free(var->datum.vector);
                break;
        }
}

void
radtest_send(int port, int code, Variable *var)
{
        RADIUS_REQ *auth;
        
        if (reply_list)
                avl_free(reply_list);
        reply_list = NULL;
        reply_code = 0;
        
        if (var->type != Vector) {
                parse_error(_("wrong datatype: expected vector"));
                return;
        }

        auth = rad_clt_send(srv_queue,
                            port,
                            code, var->datum.vector);
        if (!auth)
                return;

        reply_code = auth->code;
        var = (Variable*)sym_lookup(vartab, "REPLY_CODE");
        var->type = Integer;
        var->datum.number = reply_code;

        reply_list = avl_dup(auth->request);
        var = (Variable*)sym_lookup(vartab, "REPLY");
        var->type = Vector;
        var->datum.vector = NULL;
        var->datum.vector = reply_list;
        radreq_free(auth);
}

/* FIXME: duplicated in radiusd/files.c */
int
comp_op(int op, int result)
{
        switch (op) {
        default:
        case OPERATOR_EQUAL:
                if (result != 0)
                        return -1;
                break;

        case OPERATOR_NOT_EQUAL:
                if (result == 0)
                        return -1;
                break;

        case OPERATOR_LESS_THAN:
                if (result >= 0)
                        return -1;
                break;

        case OPERATOR_GREATER_THAN:
                if (result <= 0)
                        return -1;
                break;
                    
        case OPERATOR_LESS_EQUAL:
                if (result > 0)
                        return -1;
                break;
                        
        case OPERATOR_GREATER_EQUAL:
                if (result < 0)
                        return -1;
                break;
        }
        return 0;
}

int
compare_lists(VALUE_PAIR *reply, VALUE_PAIR *sample)
{
        int result = 0;
        
        for (; sample && result == 0; sample = sample->next) {
                VALUE_PAIR *p;

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

