/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

/* This file deals with contents of /etc/raddb directory (except config and
   dictionaries) */

#define RADIUS_MODULE_FILES_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <radiusd.h>
#include <radutmp.h>
#include <symtab.h>
#include <parser.h>
#include <checkrad.h>
#ifdef USE_SQL
# include <radsql.h>
#endif
#include <raddbm.h>
#include <obstack1.h>

/*
 * Symbol tables and lists
 */
Symtab          *user_tab;     /* raddb/users  */
Symtab          *deny_tab;     /* raddb/access.deny */

MATCHING_RULE   *huntgroups;   /* raddb/huntgroups */ 
MATCHING_RULE   *hints;        /* raddb/hints */
RAD_LIST /* of CLIENT */ *clients; /* raddb/clients */
RAD_LIST /* of RADCK_TYPE */ *radck_type;   /* raddb/nastypes */

static struct keyword op_tab[] = {
        { "=", OPERATOR_EQUAL },
        { "!=", OPERATOR_NOT_EQUAL },
        { ">", OPERATOR_GREATER_THAN },
        { "<", OPERATOR_LESS_THAN },
        { ">=", OPERATOR_GREATER_EQUAL },
        { "<=", OPERATOR_LESS_EQUAL },
        { 0 }
};

int paircmp(RADIUS_REQ *req, VALUE_PAIR *check, char *pusername);
int fallthrough(VALUE_PAIR *vp);
/*
 * Static declarations
 */
static int portcmp(VALUE_PAIR *check, VALUE_PAIR *request);
static int groupcmp(RADIUS_REQ *req, char *groupname, char *username);
static int uidcmp(VALUE_PAIR *check, char *username);
static void matchrule_free(MATCHING_RULE **pl);
static int matches(RADIUS_REQ *req, char *name, MATCHING_RULE *pl, char *matchpart);
static int huntgroup_match(RADIUS_REQ *req, char *huntgroup);
static int user_find_sym(char *name, RADIUS_REQ *req, 
                         VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);
#ifdef USE_DBM
int user_find_db(char *name, RADIUS_REQ *req,
                        VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);
#endif
static MATCHING_RULE *file_read(int cf_file, char *name);

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

/* ***************************************************************************
 * raddb/users
 */

/*
 * parser
 */
int
add_user_entry(Symtab *symtab, char *filename, int line,
	       char *name, VALUE_PAIR *check, VALUE_PAIR *reply)
{
        User_symbol *sym;

        /* Special handling for DEFAULT names: strip any trailing
         * symbols
         */
        if (strncmp(name, "DEFAULT", 7) == 0) 
                name = "DEFAULT";
        if (strncmp(name, "BEGIN", 5) == 0) 
                name = "BEGIN";

        if ((check == NULL && reply == NULL)
            || fix_check_pairs(CF_USERS, filename, line, name, &check)
            || fix_reply_pairs(CF_USERS, filename, line, name, &reply)) {
                radlog(L_ERR,
                       _("%s:%d: discarding user `%s'"),
                       filename,
                       line, name);
                avl_free(check);
                avl_free(reply);
                return 0;
        }

        sym = sym_install(symtab, name);
        
        sym->check = check;
        sym->reply = reply;
        sym->lineno = line;
        return 0;
}

static int
free_user_entry(User_symbol *sym)
{
        avl_free(sym->check);
        avl_free(sym->reply);
        return 0;
}

struct temp_list {
        int cf_file;
        MATCHING_RULE *head;
        MATCHING_RULE *tail;
};

int
add_pairlist(struct temp_list *closure, char *filename, int line,
	     char *name, VALUE_PAIR *lhs, VALUE_PAIR *rhs)
{
        MATCHING_RULE *pl;
        
        if ((lhs == NULL && rhs == NULL)
            || fix_check_pairs(closure->cf_file, filename, line, name, &lhs)
            || fix_reply_pairs(closure->cf_file, filename, line, name, &rhs)) {
                radlog(L_ERR,
                       _("%s:%d: discarding entry `%s'"),
                       filename,
                       line, name);
                avl_free(lhs);
                avl_free(rhs);
                return 0;
        }

        pl = emalloc(sizeof(MATCHING_RULE));
        pl->name = estrdup(name);
        pl->lhs = lhs;
        pl->rhs = rhs;
        pl->lineno = line;
        if (closure->tail)
                closure->tail->next = pl;
        else
                closure->head = pl;
        closure->tail = pl;
        return  0;
}

int
read_users(char *name)
{
        if (!user_tab)
                user_tab = symtab_create(sizeof(User_symbol), free_user_entry);
        return parse_file(name, user_tab, add_user_entry);
}

MATCHING_RULE *
file_read(int cf_file, char *name)
{
        struct temp_list tmp;

        tmp.cf_file = cf_file;
        tmp.head = tmp.tail = NULL;
        parse_file(name, &tmp, add_pairlist);
        return tmp.head;
}

enum lookup_state {
        LU_begin,
        LU_match,
        LU_default
};

typedef struct {
        char *name;
        enum lookup_state state;
        User_symbol *sym;
} USER_LOOKUP;


static User_symbol * user_lookup(char *name, USER_LOOKUP *lptr);
static User_symbol * user_next(USER_LOOKUP *lptr);

/*
 * Hash lookup
 */
User_symbol *
user_lookup(char *name, USER_LOOKUP *lptr)
{
        lptr->name = name;
        lptr->state = LU_begin;
        lptr->sym = sym_lookup(user_tab, "BEGIN");
        return lptr->sym ? lptr->sym : user_next(lptr);
}

User_symbol *
user_next(USER_LOOKUP *lptr)
{
        if (lptr->sym && (lptr->sym = sym_next((Symbol*)lptr->sym)))
                return lptr->sym;
        
        switch (lptr->state) {
        case LU_begin:
                lptr->sym = sym_lookup(user_tab, lptr->name);
                if (lptr->sym) {
                        lptr->state = LU_match;
                        break;
                }
                /*FALLTHRU*/
        case LU_match:
                lptr->state = LU_default;
                lptr->sym = sym_lookup(user_tab, "DEFAULT");
                break;
                
        case LU_default:
                break;
        }
        return lptr->sym;
}


static int match_user(User_symbol *sym, RADIUS_REQ *req,
                      VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);

/*
 * Find matching profile in the hash table
 */
int
user_find_sym(char *name, RADIUS_REQ *req,
	      VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
        int found = 0;
        User_symbol *sym;
        USER_LOOKUP lu;
        
        debug(1,("looking for %s", name));
        for (sym = user_lookup(name, &lu); sym; sym = user_next(&lu)) {
                if (match_user(sym, req, check_pairs, reply_pairs)) {
                        found = 1;
                        if (!fallthrough(sym->reply))
                                break;
                        debug(1, ("fall through"));
                        lu.sym = NULL; /* force jump to next state */
                }
        }
        debug(1, ("returning %d", found));
        return found;
}

int
match_user(User_symbol *sym, RADIUS_REQ *req,
	   VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
        VALUE_PAIR *p;
        VALUE_PAIR *check_tmp;
        VALUE_PAIR *reply_tmp;
        int found;
        
        if (!sym)
                return 0;

        found = 0;
        do {
                check_tmp = avl_dup(sym->check);
#ifdef USE_SQL
                rad_sql_check_attr_query(req, &check_tmp);
#endif
                if (paircmp(req, check_tmp, NULL)) {
                        avl_free(check_tmp);
                        continue;
                }

                found = 1;

                for (p = avl_find(sym->check, DA_MATCH_PROFILE);
                     p; 
                     p = avl_find(p->next, DA_MATCH_PROFILE)) {
                        debug(1, ("submatch: %s", p->avp_strvalue));

                        found = match_user(sym_lookup(user_tab, p->avp_strvalue),
                                           req, check_pairs, reply_pairs);
                }                       

                if (!found) {
                        avl_free(check_tmp);
                        continue;
                }       

                reply_tmp = avl_dup(sym->reply);
                avl_merge(reply_pairs, &reply_tmp);
                avl_merge(check_pairs, &check_tmp);
#ifdef USE_SQL
                rad_sql_reply_attr_query(req, reply_pairs);
#endif

                avl_free(reply_tmp);
                avl_free(check_tmp);

                for (p = avl_find(sym->reply, DA_MATCH_PROFILE);
                     p;
                     p = avl_find(p->next, DA_MATCH_PROFILE)) {
                        debug(1, ("next: %s", p->avp_strvalue));
                        match_user(sym_lookup(user_tab, p->avp_strvalue),
                                   req, check_pairs, reply_pairs);
                }
                if (!fallthrough(sym->reply))
                        break;
                debug(1, ("fall through near line %d", sym->lineno));
        } while (sym = sym_next((Symbol*)sym));

        return found;
}

/*
 * Find the named user in the database.  Create the
 * set of attribute-value pairs to check and reply with
 * for this user from the database. The password verification
 * is done by the caller. user_find() only compares attributes.
 */
int
user_find(char *name, RADIUS_REQ *req,
	  VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
        int found = 0;

        /* 
         *      Check for valid input, zero length names not permitted 
         */
        if (name[0] == 0) {
                radlog(L_ERR, _("zero length username not permitted"));
                return -1;
        }

        /*
         *      Find the entry for the user.
         */
#ifdef USE_DBM
        if (use_dbm) 
                found = user_find_db(name, req, check_pairs, reply_pairs);
        else
#endif
                found = user_find_sym(name, req, check_pairs, reply_pairs);

        /*
         *      See if we succeeded.
         */
        if (!found)
                return -1;

        /*
         *      Remove server internal parameters.
         */
        avl_delete(reply_pairs, DA_FALL_THROUGH);
        avl_delete(reply_pairs, DA_MATCH_PROFILE);
        
        return 0;
}

/*
 * Standalone parser for the output of Exec-Process-Wait calls
 */

/* States of the automaton
 */
#define PS_LHS 0     /* expect left-hand side*/
#define PS_OPS 1     /*  --"-- operation */
#define PS_RHS 2     /*  --"-- right=hand side */
#define PS_END 3     /*  --"-- end of input */

#define isws(c) (c == ' ' || c == '\t')
#define isdelim(c) (isws(c) || c == '\n' || c == ',' || c == '=')

/*
 * Obtain next token from the input string
 */

static int
nextkn(char **sptr, char *token, int toksize)
{
        char *start;
        
        /* skip whitespace */
        while (**sptr && isws(**sptr))
                ++(*sptr);
        if (!*sptr)
                return 0;
        start = token;
        if (**sptr == '"') {
                (*sptr)++;
                while (toksize && **sptr) {
                        if (**sptr == '\\' && (*sptr)[1]) {
                                switch (*++*sptr) {
                                default:
                                        *token++ = **sptr;
                                        break;
                                case 'a':
                                        *token++ = '\a';
                                        break;
                                case 'b':
                                        *token++ = '\b';
                                        break;
                                case 'f':
                                        *token++ = '\f';
                                        break;
                                case 'n':
                                        *token++ = '\n';
                                        break;
                                case 'r':
                                        *token++ = '\r';
                                        break;
                                case 't':
                                        *token++ = '\t';
                                        break;
                                case 'v':
                                        *token++ = '\v';
                                }
                                ++*sptr;
                                toksize--;
			} else if (**sptr == '"') {
				++*sptr;
				break;
                        } else 
                                *token++ = *(*sptr)++;
                }
        } else if (**sptr == ',' || **sptr == '=' || **sptr == '\n') {
                *token++ = *(*sptr)++;
        } else {
                while (toksize && **sptr && !isdelim(**sptr)) {
                        *token++ = *(*sptr)++;
                        toksize--;
                }
        }
        *token = 0;
        return start[0];
}

/*
 * Parse buffer as a pairlist. Put resulting pairs into the variable pointed
 * to by first_pair. 
 * Return 0 if OK, otherwise return -1 and put error message (if any)
 * in errmsg.
 */
int
userparse(char *buffer, VALUE_PAIR **first_pair, char **errmsg)
{
        int             state;
        DICT_ATTR       *attr = NULL;
        VALUE_PAIR      *pair;
        int             op;
        static char errbuf[512];
        char token[256];

        state = PS_LHS;
        while (nextkn(&buffer, token, sizeof(token))) {
                switch (state) {
                case PS_LHS:
                        if (token[0] == '\n' || token[0] == '#')
                                continue;
                        if (!(attr = attr_name_to_dict(token))) {
                                snprintf(errbuf, sizeof(errbuf),
                                        _("unknown attribute `%s/%s'"), 
                                        token, buffer);
                                *errmsg = errbuf; 
                                return -1;
                        }
                        state = PS_OPS;
                        break;
                        
                case PS_OPS:
                        op = xlat_keyword(op_tab, token, -1);
                        if (op == -1) {
                                snprintf(errbuf, sizeof(errbuf),
                                        _("expected opcode but found %s"),
                                        token);
                                *errmsg = errbuf; 
                                return -1;
                        }
                        state = PS_RHS;
                        break;
                        
                case PS_RHS:
			pair = install_pair("<stdin>", 0, attr->name, 
                                             op, token);
			if (!pair) {
				snprintf(errbuf, sizeof(errbuf),
				         _("install_pair failed on %s"),
					 attr->name);
				return -1;
			}
                        avl_merge(first_pair, &pair);
                        state = PS_END;
                        break;
                        
                case PS_END:
                        if (token[0] != ',' && token[0] != '\n') {
                                snprintf(errbuf, sizeof(errbuf),
                                        _("expected , but found %s"),
                                        token);
                                *errmsg = errbuf;
                                return -1;
                        }
                        state = PS_LHS;
                        break;
                }
        }
        return 0;
}

/* ***************************************************************************
 * raddb/hints
 */

/*
 *      Add hints to the info sent by the terminal server
 *      based on the pattern of the username.
 */
int
hints_setup(RADIUS_REQ *req)
{
        VALUE_PAIR      *request_pairs = req->request;
        char            newname[AUTH_STRING_LEN];
        VALUE_PAIR      *name_pair;
        VALUE_PAIR      *orig_name_pair;
        VALUE_PAIR      *tmp;
        MATCHING_RULE   *i;
        int             matched = 0;

	/* Add Proxy-Replied pair if necessary */
        switch (req->code) {
	case RT_AUTHENTICATION_ACK:
	case RT_AUTHENTICATION_REJECT:
	case RT_ACCOUNTING_RESPONSE:
	case RT_ACCESS_CHALLENGE:
		tmp = avp_create_integer(DA_PROXY_REPLIED, 1);
		avl_merge(&request_pairs, &tmp);
		avp_free(tmp);
		break;

	case RT_STATUS_SERVER:
		return 0;
	}
	
        if (hints == NULL)
                return 0;

        /* 
         *      Check for valid input, zero length names not permitted 
         */
        if ((name_pair = avl_find(request_pairs, DA_USER_NAME)) == NULL) {
		name_pair = avp_create_string(DA_USER_NAME, "");
                orig_name_pair = NULL;
        } else {
                orig_name_pair = avp_create_string(DA_ORIG_USER_NAME,
						   name_pair->avp_strvalue);
	}

        debug(1, ("called for `%s'", name_pair->avp_strvalue));
        
        /* if Framed-Protocol is present but Service-Type is missing, add
           Service-Type = Framed-User. */
        if (avl_find(request_pairs, DA_FRAMED_PROTOCOL) != NULL &&
            avl_find(request_pairs, DA_SERVICE_TYPE) == NULL) {
                tmp = avp_create_integer(DA_SERVICE_TYPE,
                                         DV_SERVICE_TYPE_FRAMED_USER);
                if (tmp) 
                        avl_merge(&request_pairs, &tmp);
        }

        for (i = hints; i; i = i->next) {
                int do_strip;
                VALUE_PAIR *add;
                
                if (matches(req, name_pair->avp_strvalue, i, newname))
                        continue;

                matched++;
                
                debug(1, ("matched %s at hints:%d", i->name, i->lineno));
        
                add = avl_dup(i->rhs);
        
                /* See if we need to adjust the name. */
                do_strip = 1;
                if ((tmp = avl_find(i->rhs, DA_STRIP_USER_NAME)) != NULL
                    || (tmp = avl_find(i->lhs, DA_STRIP_USER_NAME)) != NULL)
                        do_strip = tmp->avp_lvalue;
                
                if (do_strip) 
                        string_replace(&name_pair->avp_strvalue, newname);

                /* Ok, let's see if we need to further modify the username */
                if ((tmp = avl_find(i->rhs, DA_REPLACE_USER_NAME))
                    || (tmp = avl_find(i->lhs, DA_REPLACE_USER_NAME))) {
                        char *ptr;
                        struct obstack hints_stk;
 
                        obstack_init(&hints_stk);
                        ptr = radius_xlate(&hints_stk, tmp->avp_strvalue,
                                           req, NULL);
                        if (ptr) 
                                string_replace(&name_pair->avp_strvalue, ptr);
                        obstack_free(&hints_stk, NULL);
                }
                
                /* Is the rewrite function specified? */
                if ((tmp = avl_find(i->rhs, DA_REWRITE_FUNCTION))
                    || (tmp = avl_find(i->lhs, DA_REWRITE_FUNCTION))) {
                        if (rewrite_eval(tmp->avp_strvalue, req, NULL, NULL)) {
                                radlog(L_ERR, "hints:%d: %s(): %s",
                                       i->lineno,
                                       tmp->avp_strvalue,
				       _("not defined"));
                        }
                }

                debug(1, ("new name is `%s'", name_pair->avp_strvalue));

                /* fix-up the string length */
                name_pair->avp_strlength = strlen(name_pair->avp_strvalue);

                /* Add all attributes to the request list, except
                 * DA_STRIP_USER_NAME and DA_REPLACE_USER_NAME */
                avl_delete(&add, DA_STRIP_USER_NAME);
                avl_delete(&add, DA_REPLACE_USER_NAME);
                avl_delete(&add, DA_REWRITE_FUNCTION);
                avl_merge(&request_pairs, &add);
                avl_free(add);
                
                /* Ok, let's see if we need to further check the
                   hint's rules */
                if (((tmp = avl_find(i->rhs, DA_FALL_THROUGH)) != NULL
                     || (tmp = avl_find(i->lhs, DA_FALL_THROUGH)) != NULL)
                    && tmp->avp_lvalue)
                        continue;
                break;
        }

        if (matched) {
		if (orig_name_pair)
			avl_add_pair(&request_pairs, orig_name_pair);
		else
			avl_add_pair(&request_pairs, name_pair);
	} else {
		if (orig_name_pair)
			avp_free(orig_name_pair);
		else
			avp_free(name_pair);
	}

        req->request = request_pairs;
	
        return 0;
}

/* ***************************************************************************
 * raddb/huntgroups
 */

/*
 * See if the huntgroup matches.
 */
int
huntgroup_match(RADIUS_REQ *req, char *huntgroup)
{
        MATCHING_RULE *pl;
        
        for (pl = huntgroups; pl; pl = pl->next) {
                if (strcmp(pl->name, huntgroup) != 0)
                        continue;
                if (paircmp(req, pl->lhs, NULL) == 0) {
                        debug(1, ("matched %s at huntgroups:%d",
                                 pl->name, pl->lineno));
                        break;
                }
        }

        return (pl != NULL);
}


/*
 * See if we have access to the huntgroup.
 * Return:  0 if we don't have access.
 *          1 if we do have access.
 *         -1 on error.
 */
int
huntgroup_access(RADIUS_REQ *radreq)
{
        VALUE_PAIR      *pair;
        MATCHING_RULE   *pl;
        int             r = 1;

        if (huntgroups == NULL)
                return 1;

        for (pl = huntgroups; pl; pl = pl->next) {
                /*
                 *      See if this entry matches.
                 */
                if (paircmp(radreq, pl->lhs, NULL) != 0)
                        continue;
                debug(1, ("matched huntgroup at huntgroups:%d", pl->lineno));
                r = paircmp(radreq, pl->rhs, NULL) == 0;
                break;
        }

#ifdef DA_REWRITE_FUNCTION
        if (pl &&
            (pair = avl_find(pl->lhs, DA_REWRITE_FUNCTION)) != NULL) {
                if (rewrite_eval(pair->avp_strvalue, radreq, NULL, NULL)) {
                        radlog(L_ERR, "huntgroups:%d: %s(): %s",
                               pl->lineno,
                               pair->avp_strvalue,
			       _("not defined"));
                }
        }
#endif  

        debug(1, ("returning %d", r));
        return r;
}

int
read_naslist_file(char *file)
{
#ifdef USE_SNMP 
        snmp_init_nas_stat();
#endif
        return nas_read_file(file);
}

/* ***************************************************************************
 * raddb/clients
 */

/*
 * parser
 */
/*ARGSUSED*/
int
read_clients_entry(void *u ARG_UNUSED, int fc, char **fv,
		   char *file, int lineno)
{
        CLIENT *cp;
        
        if (fc != 2) {
                radlog(L_ERR, "%s:%d: %s",
                       file, lineno,
		       _("wrong number of fields"));
                return -1;
        }

        cp = emalloc(sizeof(CLIENT));

        cp->ipaddr = ip_gethostaddr(fv[0]);
        cp->secret = estrdup(fv[1]);
        if (fc == 3)
                STRING_COPY(cp->shortname, fv[2]);
        ip_gethostname(cp->ipaddr, cp->longname, sizeof(cp->longname));
	list_append(clients, cp);
        return 0;
}

static int
client_free(void *item, void *data ARG_UNUSED)
{
        CLIENT *cl = item;
	efree(cl->secret);
	efree(cl);
	return 0;
}

/*
 * Read the clients file.
 */
int
read_clients_file(char *file)
{
	list_destroy(&clients, client_free, NULL);
	clients = list_create();
        return read_raddb_file(file, 1, read_clients_entry, NULL);
}


/*
 * Find a client in the CLIENTS list.
 */
CLIENT *
client_lookup_ip(UINT4 ipaddr)
{
        CLIENT *cl;
	ITERATOR *itr = iterator_create(clients);

	if (!itr)
		return NULL;
        for (cl = iterator_first(itr); cl; cl = iterator_next(itr))
                if (ipaddr == cl->ipaddr)
                        break;
	iterator_destroy(&itr);
        return cl;
}


/*
 * Find the name of a client (prefer short name).
 */
char *
client_lookup_name(UINT4 ipaddr, char *buf, size_t bufsize)
{
        CLIENT *cl;

        if ((cl = client_lookup_ip(ipaddr)) != NULL) {
                if (cl->shortname[0])
                        return cl->shortname;
                else
                        return cl->longname;
        }
        return ip_gethostname(ipaddr, buf, bufsize);
}

/* ****************************************************************************
 * raddb/nastypes
 */


/*
 * parser
 */
/*ARGSUSED*/
int
read_nastypes_entry(void *u ARG_UNUSED, int fc, char **fv,
		    char *file, int lineno)
{
        RADCK_TYPE *mp;
        int method;

        if (fc < 2) {
                radlog(L_ERR, "%s:%d: %s", file, lineno,
		       _("too few fields"));
                return -1;
        }

        if (strcmp(fv[1], "finger") == 0)
                method = METHOD_FINGER;
        else if (strcmp(fv[1], "snmp") == 0)
                method = METHOD_SNMP;
        else if (strcmp(fv[1], "ext") == 0)
                method = METHOD_EXT;
        else {
                radlog(L_ERR, "%s:%d: %s", file, lineno, _("unknown method"));
                return -1;
        }
                        
        mp = emalloc(sizeof(*mp));
        mp->type = estrdup(fv[0]);
        mp->method = method;
        if (fc > 2)
                mp->args = envar_parse_argcv(fc-2, &fv[2]);
        else
                mp->args = NULL;
	list_append(radck_type, mp);
        return 0;
}
        
static int
free_radck_type(void *item, void *data ARG_UNUSED)
{
        RADCK_TYPE *rp = item;

        efree(rp->type);
        envar_free_list(&rp->args);
	efree(rp);
	return 0;
}

int
read_nastypes_file(char *file)
{
	list_destroy(&radck_type, free_radck_type, NULL);
	radck_type = list_create();
        return read_raddb_file(file, 0, read_nastypes_entry, NULL);
}

RADCK_TYPE *
find_radck_type(char *name)
{
        RADCK_TYPE *tp;
       	ITERATOR *itr = iterator_create(radck_type);

        if (!itr)
        	return NULL;
        for (tp = iterator_first(itr);
	     tp && strcmp(tp->type, name);
	     tp = iterator_next(itr))
                ;
        iterator_destroy(&itr);
        return tp;
}
                

/* ****************************************************************************
 * raddb/access.deny
 */

/*
 * parser
 */
void
add_deny(char *user)
{
        sym_install(deny_tab, user);
}

/*ARGSUSED*/
int
read_denylist_entry(int *denycnt, int fc, char **fv, char *file, int lineno)
{
        if (fc != 1) {
                radlog(L_ERR,
		       "%s:%d: %s",
                       file, lineno,
		       _("wrong number of fields"));
                return -1;
        }

        if (get_deny(fv[0]))
                radlog(L_ERR, _("user `%s' already found in %s"),
                    fv[0], RADIUS_DENY);
        else {
                add_deny(fv[0]);
                (*denycnt)++;
        }
        return 0;
}

void
read_deny_file()
{
        int denycnt;
        char *name;
        
        name = mkfilename(radius_dir, RADIUS_DENY);
        if (deny_tab)
                symtab_clear(deny_tab);
        else
                deny_tab = symtab_create(sizeof(Symbol), NULL);
        denycnt = 0;

        read_raddb_file(name, 0, read_denylist_entry, &denycnt);
        efree(name);
        if (denycnt)
                radlog(L_INFO,
		       ngettext ("%d user disabled",
				 "%d users disabled", denycnt), denycnt);
}

/*
 * Return 1 if the given user should be denied access
 */
int
get_deny(char *user)
{
        return sym_lookup(deny_tab, user) != NULL;
}


/* ***************************************************************************
 * Various utilities, local to this module
 */

/*
 *      See if a VALUE_PAIR list contains Fall-Through = Yes
 */
int
fallthrough(VALUE_PAIR *vp)
{
        VALUE_PAIR *tmp;

        return (tmp = avl_find(vp, DA_FALL_THROUGH)) ? tmp->avp_lvalue : 0;
}

/*
 *      Compare a portno with a range.
 */
int
portcmp(VALUE_PAIR *check, VALUE_PAIR *request)
{
        char buf[AUTH_STRING_LEN];
        char *s, *p, *save;
        int lo, hi;
        int port = request->avp_lvalue;

        strcpy(buf, check->avp_strvalue);
        s = strtok_r(buf, ",", &save);
        while(s) {
                if ((p = strchr(s, '-')) != NULL)
                        p++;
                else
                        p = s;
                lo = atoi(s);
                hi = atoi(p);
                if (lo <= port && port <= hi) {
                        return 0;
                }
                s = strtok_r(NULL, ",", &save);
        }

        return -1;
}


int
uidcmp(VALUE_PAIR *check, char *username)
{
        struct passwd pw, *pwd;
	char buffer[512];

        if (!(pwd = rad_getpwnam_r(username, &pw, buffer, sizeof buffer)))
                return -1;

        return pwd->pw_uid - check->avp_lvalue;
}

/*
 *      See if user is member of a group.
 *      We also handle additional groups.
 */
int
groupcmp(RADIUS_REQ *req, char *groupname, char *username)
{
        struct passwd pw, *pwd;
        struct group *grp;
        char **member;
        char pwbuf[512];
        int retval;

#ifdef USE_SQL
        if (rad_sql_checkgroup(req, groupname) == 0)
                return 0;
#endif

        if ((pwd = rad_getpwnam_r(username, &pw, pwbuf, sizeof pwbuf)) == NULL)
                return -1;

        if ((grp = rad_getgrnam(groupname)) == NULL)
                return -1;

        retval = (pwd->pw_gid == grp->gr_gid) ? 0 : -1;
        if (retval < 0) {
                for (member = grp->gr_mem; *member && retval; member++) {
                        if (strcmp(*member, pwd->pw_name) == 0)
                                retval = 0;
                }
        }
	efree(grp);
        return retval;
}

/*
 *      Compare prefix/suffix.
 */
int
presufcmp(VALUE_PAIR *check, char *name, char *rest)
{
        int len, namelen;
        int ret = -1;

        debug(1, ("comparing %s and %s, check->attr is %d",
                 name, check->avp_strvalue, check->attribute));

        len = strlen(check->avp_strvalue);
        switch (check->attribute) {
                case DA_PREFIX:
                        ret = strncmp(name, check->avp_strvalue, len);
                        if (ret == 0 && rest)
                                strcpy(rest, name + len);
                        break;
                case DA_SUFFIX:
                        namelen = strlen(name);
                        if (namelen < len)
                                break;
                        ret = strcmp(name + namelen - len, check->avp_strvalue);
                        if (ret == 0 && rest) {
                                strncpy(rest, name, namelen - len);
                                rest[namelen - len] = 0;
                        }
                        break;
        }
        debug(1, ("returning %d", ret));
        return ret;
}

/*
 * Attributes we skip during comparison.
 * These are "server" check items.
 */
static int server_check_items[] = {
        DA_EXPIRATION,
        DA_LOGIN_TIME,
        DA_USER_PASSWORD,
        DA_CRYPT_PASSWORD,
        DA_PASSWORD_LOCATION,
        DA_AUTH_TYPE,
        DA_PAM_AUTH,
        DA_SIMULTANEOUS_USE,
        DA_STRIP_USER_NAME,
        DA_REPLACE_USER_NAME,
#ifdef DA_REWRITE_FUNCTION
        DA_REWRITE_FUNCTION,
#endif  
#ifdef DA_ACCT_TYPE
        DA_ACCT_TYPE,
#endif
#ifdef DA_LOG_MODE_MASK
        DA_LOG_MODE_MASK,
#endif
        DA_MENU,
        DA_TERMINATION_MENU,
        DA_GROUP_NAME,
        DA_MATCH_PROFILE,
        DA_AUTH_DATA
};

int
server_attr(int attr)
{
        int i;

        for (i = 0; i < NITEMS(server_check_items); i++) 
                if (server_check_items[i] == attr)
                        return 1;       
        return 0;
}

/*
 * Compare two pair lists except for the internal server items.
 * Return 0 on match.
 */
int
paircmp(RADIUS_REQ *request, VALUE_PAIR *check, char *pusername)
{
        VALUE_PAIR *check_item = check;
        VALUE_PAIR *auth_item;
        char username[AUTH_STRING_LEN];
        int result = 0;
        int compare;
        char *save;

	if (!pusername)
		pusername = username;
	
        while (result == 0 && check_item != NULL) {
                if (server_attr(check_item->attribute)) {  
                        check_item = check_item->next;
                        continue;
                }

                if (debug_on(20)) {
                        radlog(L_DEBUG, 
                               "check_item: %s", 
                               format_pair(check_item, &save));
                        free(save);
                }

                /*
                 *      See if this item is present in the request.
                 */
                for (auth_item = request->request; auth_item; 
                                auth_item = auth_item->next) {
                        debug(30, ("trying %d", auth_item->attribute));

                        switch (check_item->attribute) {
                        case DA_PREFIX:
                        case DA_SUFFIX:
                        case DA_GROUP_NAME:
                        case DA_GROUP:
                                if (auth_item->attribute != DA_USER_NAME)
                                        continue;
                                /*FALLTHRU*/
				
                        case DA_HUNTGROUP_NAME:
                        case DA_USER_UID:
                                break;
				
                        case DA_HINT:
                                if (auth_item->attribute != check_item->attribute)
                                        continue;
                                if (strcmp(check_item->avp_strvalue,
                                           auth_item->avp_strvalue) != 0)
                                        continue;
                                break;
				
                        default:
                                if (auth_item->attribute !=
                                    check_item->attribute)
                                        continue;
                        }
                        break;
                }
                if (auth_item == NULL) {
                        result = -1;
                        continue;
                }

                if (debug_on(20)) {
                        radlog(L_DEBUG,
                               "auth_item: %s",
                               format_pair(auth_item, &save));
                        free(save);
                }

                /*
                 *      OK it is present now compare them.
                 */
                
                compare = 0;    /* default result */
                switch (check_item->type) {
                case TYPE_STRING:
                        switch (check_item->attribute) {
                        case DA_PREFIX:
                        case DA_SUFFIX:
                                strcpy(pusername, auth_item->avp_strvalue);
                                compare = presufcmp(check_item,
                                                    auth_item->avp_strvalue,
                                                    pusername);
                                break;
				
                        case DA_NAS_PORT_ID:
                                compare = portcmp(check_item, auth_item);
                                break;
				
                        case DA_GROUP_NAME:
                        case DA_GROUP:
                                strcpy(username, auth_item->avp_strvalue);
                                compare = groupcmp(request,
                                                   check_item->avp_strvalue,
                                                   username);
                                break;
				
                        case DA_HUNTGROUP_NAME:
                                compare = !huntgroup_match(request,
                                                         check_item->avp_strvalue);
                                break;
				
                        default:
                                compare = strcmp(auth_item->avp_strvalue,
                                                 check_item->avp_strvalue);
                        }
                        break;

                case TYPE_INTEGER:
                        switch (check_item->attribute) {
                        case DA_USER_UID:
                                compare = uidcmp(check_item, username);
                                break;
                        }
                        /*FALLTHRU*/
			
                case TYPE_IPADDR:
                        compare = auth_item->avp_lvalue - check_item->avp_lvalue;
                        break;
                        
                default:
                        return -1;
                        break;
                }

                debug(20, ("compare: %d", compare));

                result = comp_op(check_item->operator, compare);

                if (result == 0)
                        check_item = check_item->next;
        }

        debug(20, ("returning %d", result));
        return result;
}

/*
 * Free a MATCHING_RULE
 */
void
matchrule_free(MATCHING_RULE **pl)
{
        MATCHING_RULE *p, *next;

        for (p = *pl; p; p = next) {
                if (p->name)
                        efree(p->name);
                if (p->lhs)
                        avl_free(p->lhs);
                if (p->rhs)
                        avl_free(p->rhs);
                next = p->next;
                efree(p);
        }
        *pl = NULL;
}

/* ***************************************************************************
 * a *very* restricted version  of wildmat
 */
char *
wild_start(char *str)
{
        char *p;

        p = str;
        while (*p) {
                switch (*p) {
                case '*':
                case '?':
                        return p;
                        
                case '\\':
                        if (p[1] == '(' || p[1] == ')')
                                return p;
                        /*FALLTHRU*/
                default:
                        p++;
                }
        }
        return NULL;
}

int
match_any_chars(char **expr, char **name)
{
        char *exprp, *expr_start, *p, *namep;
        int length;
        
        exprp = *expr;
        while (*exprp && *exprp == '*')
                exprp++;
        
        expr_start = exprp;
        while (exprp[0] == '\\' && (exprp[1] == '(' || exprp[1] == ')'))
                exprp += 2;
        
        p = wild_start(exprp);
        
        if (p) 
                length = p - exprp;
        else
                length = strlen(exprp);

        if (length == 0) {
                *name += strlen(*name);
        } else {
                namep = *name + strlen(*name) - 1;
                while (namep > *name) {
                        if (strncmp(namep, exprp, length) == 0) {
                                *name = namep;
                                break;
                        }
                        namep--;
                }
        }
        *expr = (exprp == expr_start) ? p : expr_start;
        return 0;
}

int
wild_match(char *expr, char *name, char *return_name)
{
        char *curp;
        char *start_pos, *end_pos;
        int c;
        
        strcpy(return_name, name);
        start_pos = end_pos = NULL;
        curp = name;
        while (expr && *expr) {
                switch (*expr) {
                case '*':
                        expr++;
                        if (match_any_chars(&expr, &curp))
                                return curp - name + 1;
                        break;
                        
                case '?':
                        expr++;
                        if (*curp == 0)
                                return curp - name + 1;
                        curp++;
                        break;
                        
                case '\\':
                        if (expr[1] == 0) 
                                goto def;
                        c = *++expr; expr++;
                        if (c == '(') {
                                start_pos = curp;
                        } else if (c == ')') {
                                end_pos = curp;
                                if (start_pos) {
                                        int len = end_pos - start_pos;
                                        strncpy(return_name, start_pos, len);
                                        return_name += len;
                                        *return_name = 0;
                                }
                        } else {
                                if (*curp != c)
                                        return curp - name + 1;
                                curp++;
                        }
                        break;
                        
                default:
                def:
                        if (*expr != *curp)
                                return curp - name + 1;
                        expr++;
                        curp++;
                }
        }
        return *curp != 0;
}

/* ************************************************************************* */

/*
 * Match a username with a wildcard expression.
 */
int
matches(RADIUS_REQ *req, char *name, MATCHING_RULE *pl, char *matchpart)
{
	memcpy(matchpart, name, AUTH_STRING_LEN);
        if (strncmp(pl->name, "DEFAULT", 7) == 0
	    || wild_match(pl->name, name, matchpart) == 0)
                return paircmp(req, pl->lhs, matchpart);
        return 1;
}       
        
/* ****************************************************************************
 * Read all configuration files
 */

#if USE_DBM
/*
 *      See if a potential DBM file is present.
 */
static int
checkdbm(char *users, char *ext)
{
        char *buffer;
        struct stat st;
        int rc;
        
        buffer = emalloc(strlen(users) + strlen(ext) + 1);
        strcat(strcpy(buffer, users), ext);
        rc = stat(buffer, &st);
        efree(buffer);
        return rc;
}
#endif

static int reload_data(enum reload_what what, int *do_radck);

static int
realm_set_secret(RADIUS_SERVER *srv)
{
	CLIENT *client;

	if ((client = client_lookup_ip(srv->addr)) == NULL) 
		return 1;
	srv->secret = client->secret;
	return 0;
}

int
reload_data(enum reload_what what, int *do_radck)
{
        char *path;
        int   rc = 0;
        
        switch (what) {
        case reload_all:
                /* This implies reloading users, huntgroups and hints */
                rc += reload_data(reload_dict, do_radck);
                rc += reload_data(reload_clients, do_radck);
                rc += reload_data(reload_naslist, do_radck);
                rc += reload_data(reload_realms, do_radck);
                rc += reload_data(reload_deny, do_radck);
#ifdef USE_SQL
                rc += reload_data(reload_sql, do_radck);
#endif
                reload_data(reload_rewrite, do_radck);
                break;
                
        case reload_users:
                symtab_clear(user_tab);
                path = mkfilename(radius_dir, RADIUS_USERS);
        
#if USE_DBM
                if (use_dbm && radius_mode != MODE_BUILDDBM) {
                        if (access(path, 0) == 0) {
                                radlog(L_WARN,
                                       _("using only dbm: USERS NOT LOADED"));
                        }
                        *do_radck = 0;
                } else {
                        if (radius_mode != MODE_BUILDDBM
                            && (checkdbm(path, ".dir") == 0
                                || checkdbm(path, ".db") == 0))
                                radlog(L_WARN,
                    _("DBM files found but no -b flag given - NOT using DBM"));
                
#endif
                if (read_users(path)) {
                        radlog(L_CRIT, _("can't load %s: exited"), path);
                        exit(1);
                } else
                        radlog(L_INFO, _("%s reloaded."), path);
                *do_radck = 1;
#if USE_DBM
                }
#endif
                efree(path);
                break;

        case reload_dict:
                /* Non-zero result from dict_init means there was some real
                 * trouble.
                 */
                if (dict_init())
                        rc = 1;

                /* Users, huntgroups and hints should be reloaded after
                 * changing dictionary.
                 */
                rc += reload_data(reload_users, do_radck);
                rc += reload_data(reload_huntgroups, do_radck);
                rc += reload_data(reload_hints, do_radck);
                break;
                
        case reload_huntgroups:
                matchrule_free(&huntgroups);
                path = mkfilename(radius_dir, RADIUS_HUNTGROUPS);
                huntgroups = file_read(CF_HUNTGROUPS, path);
                efree(path);
                break;
                
        case reload_hints:
                matchrule_free(&hints);
                path = mkfilename(radius_dir, RADIUS_HINTS);
                hints = file_read(CF_HINTS, path);
                efree(path);
                if (!use_dbm) 
                        *do_radck = 1;
                break;
                
        case reload_clients:
                path = mkfilename(radius_dir, RADIUS_CLIENTS);
                if (read_clients_file(path) < 0)
                        rc = 1;
                efree(path);
                break;

        case reload_naslist:
                /*FIXME*/
                path = mkfilename(radius_dir, RADIUS_NASTYPES);
                read_nastypes_file(path);
                efree(path);
                /*EMXIF*/
                
                path = mkfilename(radius_dir, RADIUS_NASLIST);
                if (read_naslist_file(path) < 0)
                        rc = 1;
                efree(path);
                break;

        case reload_realms:
                path = mkfilename(radius_dir, RADIUS_REALMS);
                if (realm_read_file(path, auth_port, acct_port,
				    realm_set_secret) < 0)
                        rc = 1;
                efree(path);
                break;
                
        case reload_deny:
                read_deny_file();
                break;

#ifdef USE_SQL
        case reload_sql:
                if (rad_sql_init() != 0) {
                        radlog(L_CRIT,
                               _("SQL Error: SQL client could not be initialized"));
                        rc = -1;
                }
                break;
#endif

        case reload_rewrite:
                break;
                
        default:
                radlog(L_CRIT, _("INTERNAL ERROR: unknown reload code: %d"),
                       what);
        }
                
        return rc;
}

int
reload_config_file(enum reload_what what)
{
        int do_radck;
        int rc;

        rc = reload_data(what, &do_radck);
        if (rc == 0 && do_radck)
                radck();
        return rc;
}

/* ****************************************************************************
 * Debugging functions
 */
static void
dump_pairs(FILE *fp, VALUE_PAIR *pair)
{
        int etype;
        
        for (; pair; pair = pair->next) {
                fprintf(fp, "\t\t%s %s ", pair->name, 
                        op_tab[pair->operator].name);

                switch (pair->type) {
                case TYPE_STRING:
                        fprintf(fp, "(STRING) ");
                        break;

                case TYPE_INTEGER:
                        fprintf(fp, "(INTEGER) ");
                        break;

                case TYPE_IPADDR:
                        fprintf(fp, "(IP) ");
                        break;
                
                case TYPE_DATE:
                        fprintf(fp, "(DATE) ");
                        break;
                        
                default:
                        fprintf(fp, "(%d) ", pair->type);
                }

                if (pair->eval_type != eval_const) {
                        etype = TYPE_STRING;
                        fprintf(fp, "=");
                } else
                        etype = pair->type;
                
                switch (etype) {
                case TYPE_STRING:
                        fprintf(fp, "%s", pair->avp_strvalue);
                        break;

                case TYPE_INTEGER:
                        fprintf(fp, "%ld", pair->avp_lvalue);
                        break;

                case TYPE_IPADDR:
                        fprintf(fp, "%lx", pair->avp_lvalue);
                        break;
                
                case TYPE_DATE:
                        fprintf(fp, "%ld", pair->avp_lvalue);
                        break;
                        
                }
                fprintf(fp, "\n");
        }
}

void
dump_pair_list(FILE *fp, char *header, MATCHING_RULE *pl)
{
        fprintf(fp, "%s {\n", header);
        for ( ; pl; pl = pl->next) {
                fprintf(fp, "\t%s:\n", pl->name);
                fprintf(fp, "\tlhs {\n");
                dump_pairs(fp, pl->lhs);
                fprintf(fp, "\t}\n");

                fprintf(fp, "\trhs {\n");
                dump_pairs(fp, pl->rhs);
                fprintf(fp, "\t}\n");
        }
        fprintf(fp, "}\n");
}

int
dump_user(FILE *fp, User_symbol *sym)
{
        fprintf(fp, "\t%s:\n", sym->name);
        fprintf(fp, "\tlhs {\n");
        dump_pairs(fp, sym->check);
        fprintf(fp, "\t}\n");

        fprintf(fp, "\trhs {\n");
        dump_pairs(fp, sym->reply);
        fprintf(fp, "\t}\n");
        
        return 0;
}

void
dump_users_db()
{
        FILE *fp;
        char *name = mkfilename(radlog_dir, RADIUS_DUMPDB_NAME);
        
        fp = fopen(name, "w");
        if (!fp) {
                radlog(L_ERR|L_PERROR,
                       _("can't create parser output file `%s'"),
                       RADIUS_DUMPDB_NAME);
                efree(name);
                return;
        }

        fchmod(fileno(fp), S_IRUSR|S_IWUSR);

        fprintf(fp, "%s {\n", "users");
        symtab_iterate(user_tab, dump_user, fp);
        fprintf(fp, "}\n");

        dump_pair_list(fp, "huntgroups", huntgroups);
        dump_pair_list(fp, "hints", hints);
        radlog(L_INFO, _("dumped users database to %s"), RADIUS_DUMPDB_NAME);
        fclose(fp);
        efree(name);
}

/* ***************************************************************************
 * Various utils exported to other modules
 */

void
strip_username(int do_strip, char *name, VALUE_PAIR *check_item,
	       char *stripped_name)
{
        char tmpname[AUTH_STRING_LEN];
        char *source_ptr = name;
        VALUE_PAIR *presuf_item, *tmp;
        
        /*
         *      See if there was a Prefix or Suffix included.
         */
        if ((presuf_item = avl_find(check_item, DA_PREFIX)) == NULL)
                presuf_item = avl_find(check_item, DA_SUFFIX);
        if (presuf_item) {
                if (tmp = avl_find(check_item, DA_STRIP_USER_NAME))
                        do_strip = tmp->avp_lvalue;
                if (do_strip) { 
                        if (presufcmp(presuf_item, name, tmpname) == 0)
                                source_ptr = tmpname;
                }
        }
                
        strcpy(stripped_name, source_ptr);
}


















