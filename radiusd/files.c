/* This file is part of GNU RADIUS.
 * Copyright (C) 2000,2001, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
/*
 * This file deals with contents of /etc/raddb directory (except config and
 * dictionaries)
 */
#define RADIUS_MODULE 8
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

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

PAIR_LIST	*huntgroups;   /* raddb/huntgroups */ 
PAIR_LIST	*hints;        /* raddb/hints */
CLIENT		*clients;      /* raddb/clients */
REALM		*realms;       /* raddb/realms */ 
RADCK_TYPE      *radck_type;   /* raddb/nastypes */

static struct keyword op_tab[] = {
	"=", PW_OPERATOR_EQUAL,
	"!=", PW_OPERATOR_NOT_EQUAL,
	">", PW_OPERATOR_GREATER_THAN,
	"<", PW_OPERATOR_LESS_THAN,
	">=", PW_OPERATOR_GREATER_EQUAL,
	"<=", PW_OPERATOR_LESS_EQUAL,
	0
};

int paircmp(VALUE_PAIR *request, VALUE_PAIR *check);
int fallthrough(VALUE_PAIR *vp);
/*
 * Static declarations
 */
static int portcmp(VALUE_PAIR *check, VALUE_PAIR *request);
static int groupcmp(VALUE_PAIR *request, char *groupname, char *username);
static int uidcmp(VALUE_PAIR *check, char *username);
static int huntgroup_paircmp(VALUE_PAIR *request, VALUE_PAIR *check);
static void pairlist_free(PAIR_LIST **pl);
static int matches(VALUE_PAIR *req, char *name, PAIR_LIST *pl, char *matchpart);
static int huntgroup_match(VALUE_PAIR *request_pairs, char *huntgroup);
static void clients_free(CLIENT *cl);
static int user_find_sym(char *name, VALUE_PAIR *request_pairs, 
			 VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);
#ifdef USE_DBM
int user_find_db(char *name, VALUE_PAIR *request_pairs,
			VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);
#endif


int
comp_op(op, result)
	int op;
	int result;
{
	switch (op) {
	default:
	case PW_OPERATOR_EQUAL:
		if (result != 0)
			return -1;
		break;

	case PW_OPERATOR_NOT_EQUAL:
		if (result == 0)
			return -1;
		break;

	case PW_OPERATOR_LESS_THAN:
		if (result >= 0)
			return -1;
		break;

	case PW_OPERATOR_GREATER_THAN:
		if (result <= 0)
			return -1;
		break;
		    
	case PW_OPERATOR_LESS_EQUAL:
		if (result > 0)
			return -1;
		break;
			
	case PW_OPERATOR_GREATER_EQUAL:
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
add_user_entry(symtab, filename, line, name, check, reply)
	Symtab *symtab;
	char *filename;
	int line;
	char *name;
	VALUE_PAIR *check, *reply;
{
	User_symbol *sym, *prev, *p;

	/* Special handling for DEFAULT names: strip any trailing
	 * symbols
	 */
	if (strncmp(name, "DEFAULT", 7) == 0) 
		name = "DEFAULT";
	if (strncmp(name, "BEGIN", 5) == 0) 
		name = "BEGIN";

	if ((check == NULL && reply == NULL) ||
	    fix_check_pairs(name, line, &check) ||
	    fix_reply_pairs(name, line, &reply)) {
		radlog(L_ERR,
		       _("%s:%d: discarding user `%s'"),
		       filename,
		       line, name);
		avl_free(check);
		avl_free(reply);
		return 0;
	}

	
	/* See if there are already any entries of this type. If so,
	 * add after the last of them.
	 */
	prev = (User_symbol*)sym_lookup(symtab, name);
	if (prev) {
		p = prev;
		while ((p = p->next) != NULL && strcmp(p->name, name) == 0) 
			prev = p;
			
		sym = (User_symbol*)alloc_sym(name, symtab->elsize);
		sym->next = prev->next;
		prev->next = sym;
	} else {
		sym = (User_symbol*)sym_install(symtab, name);
	}
	
	sym->check = check;
	sym->reply = reply;
	sym->lineno = line;
	return 0;
}

static int
free_user_entry(sym)
	User_symbol *sym;
{
	avl_free(sym->check);
	avl_free(sym->reply);
	return 0;
}

struct temp_list {
	PAIR_LIST *head;
	PAIR_LIST *tail;
};

int
add_pairlist(closure, filename, line, name, check, reply)
	struct temp_list *closure;
	char *filename;
	int line;
	char *name;
	VALUE_PAIR *check, *reply;
{
	PAIR_LIST *pl;
	
	pl = Alloc_entry(PAIR_LIST);
	pl->name = estrdup(name);
	pl->check = check;
	pl->reply = reply;
	pl->lineno = line;
	if (closure->tail)
		closure->tail->next = pl;
	else
		closure->head = pl;
	closure->tail = pl;
	return  0;
}

int
read_users(name)
	char *name;
{
	if (!user_tab)
		user_tab = symtab_create(sizeof(User_symbol), 0,
					 free_user_entry);
	return parse_file(name, user_tab, add_user_entry);
}

PAIR_LIST *
file_read(name)
	char *name;
{
	struct temp_list tmp;

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
user_lookup(name, lptr)
	char *name;
	USER_LOOKUP *lptr;
{
	lptr->name = name;
	lptr->state = LU_begin;
	lptr->sym = (User_symbol*)sym_lookup(user_tab, "BEGIN");
	return lptr->sym ? lptr->sym : user_next(lptr);
}

User_symbol *
user_next(lptr)
	USER_LOOKUP *lptr;
{
	if (lptr->sym &&
	    (lptr->sym = (User_symbol*)sym_next((Symbol*)lptr->sym)))
		return lptr->sym;
	
	switch (lptr->state) {
	case LU_begin:
		lptr->sym = (User_symbol*)sym_lookup(user_tab, lptr->name);
		if (lptr->sym) {
			lptr->state = LU_match;
			break;
		}
		/*FALLTHRU*/
	case LU_match:
		lptr->state = LU_default;
		lptr->sym = (User_symbol*)sym_lookup(user_tab, "DEFAULT");
		break;
		
	case LU_default:
		break;
	}
	return lptr->sym;
}


static int match_user(User_symbol *sym, VALUE_PAIR *request_pairs,
		      VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);

/*
 * Find matching profile in the hash table
 */
int
user_find_sym(name, request_pairs, check_pairs, reply_pairs)
	char       *name;
	VALUE_PAIR *request_pairs;
	VALUE_PAIR **check_pairs;
	VALUE_PAIR **reply_pairs;
{
	int found = 0;
	User_symbol *sym;
	USER_LOOKUP lu;
	
	for (sym = user_lookup(name, &lu); sym; sym = user_next(&lu)) {
		if (match_user(sym, request_pairs, check_pairs, reply_pairs)) {
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
match_user(sym, request_pairs, check_pairs, reply_pairs)
	User_symbol *sym;
	VALUE_PAIR *request_pairs;
	VALUE_PAIR **check_pairs;
	VALUE_PAIR **reply_pairs;
{
	VALUE_PAIR *p;
	VALUE_PAIR *check_tmp;
	VALUE_PAIR *reply_tmp;
	int found;
	
	if (!sym)
		return 0;

	found = 0;
	do {
		if (paircmp(request_pairs, sym->check))
			continue;
		
		if (p = avl_find(sym->check, DA_MATCH_PROFILE)) {
			debug(1, ("submatch: %s", p->strvalue));

			if (!match_user((User_symbol*)sym_lookup(user_tab,
								 p->strvalue),
					request_pairs, check_pairs,
					reply_pairs))
				continue;
		}			

		found = 1;

		check_tmp = avl_dup(sym->check);
		reply_tmp = avl_dup(sym->reply);
		avl_merge(reply_pairs, &reply_tmp);
		avl_merge(check_pairs, &check_tmp);
#ifdef USE_SQL
		rad_sql_attr_query(request_pairs, reply_pairs);
#endif

		avl_free(reply_tmp);
		avl_free(check_tmp);

		if (p = avl_find(sym->reply, DA_MATCH_PROFILE)) {
			debug(1, ("next: %s", p->strvalue));
			match_user((User_symbol*)sym_lookup(user_tab,
							    p->strvalue),
				   request_pairs, check_pairs, reply_pairs);
		}
		if (!fallthrough(sym->reply))
			break;
		debug(1, ("fall through"));
	} while (sym = (User_symbol*)sym_next((Symbol*)sym));

	return found;
}


/*
 * Find the named user in the database.  Create the
 * set of attribute-value pairs to check and reply with
 * for this user from the database. The password verification
 * is done by the caller. user_find() only compares attributes.
 */
int
user_find(name, request_pairs, check_pairs, reply_pairs)
	char       *name;
	VALUE_PAIR *request_pairs;
	VALUE_PAIR **check_pairs;
	VALUE_PAIR **reply_pairs;
{
	int		found = 0;

	/* 
	 *	Check for valid input, zero length names not permitted 
	 */
	if (name[0] == 0) {
		radlog(L_ERR, _("zero length username not permitted"));
		return -1;
	}

	/*
	 *	Find the entry for the user.
	 */
#ifdef USE_DBM
	if (use_dbm) 
		found = user_find_db(name,
				     request_pairs, check_pairs, reply_pairs);
	else
#endif
		found = user_find_sym(name, 
				      request_pairs, check_pairs, reply_pairs);

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		return -1;

	/*
	 *	Remove server internal parameters.
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
#define isdelim(c) (isws(c) || c == '\n' || c == ',')

/*
 * Obtain next token from the input string
 */
static int nextkn(char **sptr, char *token, int toksize);

int
nextkn(sptr, token, toksize)
	char **sptr;
	char *token;
	int toksize;
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
		while (toksize && **sptr && **sptr != '"') {
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
			} else 
				*token++ = *(*sptr)++;
		}
	} else if (**sptr == ',' || **sptr == '\n') {
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
userparse(buffer, first_pair, errmsg)
	char *buffer;
	VALUE_PAIR **first_pair;
	char **errmsg;
{
	int		state;
	int		x;
	char		*s;
	DICT_ATTR	*attr = NULL;
	DICT_VALUE	*dval;
	VALUE_PAIR	*pair, *pair2;
	struct tm	*tm;
	time_t		timeval;
	int		op;
	static char errbuf[512];
	char token[256];

	state = PS_LHS;
	while (nextkn(&buffer, token, sizeof(token))) {
		switch (state) {
		case PS_LHS:
			if (token[0] == '\n' || token[0] == '#')
				continue;
			if (!(attr = attr_name_to_dict(token))) {
				radsprintf(errbuf, sizeof(errbuf),
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
				radsprintf(errbuf, sizeof(errbuf),
					_("expected opcode but found %s"),
					token);
				*errmsg = errbuf; 
				return -1;
			}
			state = PS_RHS;
			break;
			
		case PS_RHS:
			pair = avp_alloc();
			pair->name = attr->name;
			pair->attribute = attr->value;
			pair->type = attr->type;
			pair->operator = op;

			switch (pair->type) {

			case PW_TYPE_STRING:
				pair->strvalue = make_string(token);
				pair->strlength = strlen(pair->strvalue);
				break;

			case PW_TYPE_INTEGER:
				/*
				 *	For DA_NAS_PORT_ID, allow a
				 *	port range instead of just a port.
				 */
				if (attr->value == DA_NAS_PORT_ID) {
					for (s = token; *s; s++)
						if (!isdigit(*s))
							break;
					if (*s) {
						pair->type = PW_TYPE_STRING;
						pair->strvalue = make_string(token);
						pair->strlength = strlen(pair->strvalue);
						break;
					}
				}
				if (isdigit(*token)) {
					pair->lvalue = atoi(token);
				} else if (!(dval = value_name_to_value(token))) {
					avp_free(pair);
					radsprintf(errbuf, sizeof(errbuf),
						_("unknown value %s"),
						token);
					*errmsg = errbuf;
					return -1;
				} else {
					pair->lvalue = dval->value;
				}
				break;

			case PW_TYPE_IPADDR:
				if (pair->attribute != DA_FRAMED_IP_ADDRESS) {
					pair->lvalue = get_ipaddr(token);
					break;
				}

				/*
				 * We allow a "+" at the end to	indicate that
				 * we should add the portno. to the IP address.
				 */
				x = 0;
				if (token[0]) {
					for(s = token; s[1]; s++)
						;
					if (*s == '+') {
						*s = 0;
						x = 1;
					}
				}
				pair->lvalue = get_ipaddr(token);

				/*
				 *	Add an extra (hidden) attribute.
				 */
				pair2 = avp_alloc();
				
				pair2->name = "Add-Port-To-IP-Address";
				pair2->attribute = DA_ADD_PORT_TO_IP_ADDRESS;
				pair2->type = PW_TYPE_INTEGER;
				pair2->lvalue = x;
				pair2->next = pair;
				pair = pair2;
				break;

			case PW_TYPE_DATE:
				timeval = time(NULL);
				tm = localtime(&timeval);
				if (user_gettime(token, tm)) {
					radsprintf(errbuf, sizeof(errbuf),
						_("%s: error parsing date %s"),
						attr->name, token);	
					goto error;
				}
#ifdef TIMELOCAL
				pair->lvalue = (UINT4)timelocal(tm);
#else /* TIMELOCAL */
				pair->lvalue = (UINT4)mktime(tm);
#endif /* TIMELOCAL */
				break;

			default:
				radsprintf(errbuf, sizeof(errbuf),
					_("unknown attribute type %d"),
					pair->type);
			error:
				*errmsg = errbuf;
				avp_free(pair);
				return -1;
			}
			avl_add_list(first_pair, pair);
			state = PS_END;
			break;
			
		case PS_END:
			if (token[0] != ',' && token[0] != '\n') {
				radsprintf(errbuf, sizeof(errbuf),
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

static struct obstack hints_stk;
static int hints_stk_ready;

/*
 *	Add hints to the info sent by the terminal server
 *	based on the pattern of the username.
 */
int
hints_setup(request_pairs)
	VALUE_PAIR *request_pairs;
{
	char		newname[AUTH_STRING_LEN];
	char		*name;
	VALUE_PAIR      *name_pair;
	VALUE_PAIR      *orig_name_pair;
	VALUE_PAIR	*add;
	VALUE_PAIR	*last;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*i;
	int		do_strip;

	if (hints == NULL)
		return 0;

	/* 
	 *	Check for valid input, zero length names not permitted 
	 */
	if ((name_pair = avl_find(request_pairs, DA_USER_NAME)) == NULL) {
		name = NULL;
		orig_name_pair = NULL;
	} else {
		name = name_pair->strvalue;
		orig_name_pair = avp_dup(name_pair);
		orig_name_pair->attribute = DA_ORIG_USER_NAME;
		orig_name_pair->name = "Orig-User-Name";
	}
	
	if (name == NULL || name[0] == 0)
		/*
		 *	Will be complained about later.
		 */
		return 0;

	debug(1, ("called for `%s'", name));
	
	/*
	 * if Framed-Protocol is present but Service-Type is missing, add
	 * Service-Type = Framed-User.
	 */
	if (avl_find(request_pairs, DA_FRAMED_PROTOCOL) != NULL &&
	    avl_find(request_pairs, DA_SERVICE_TYPE) == NULL) {
		tmp = avp_create(DA_SERVICE_TYPE, 0, NULL,
				  DV_SERVICE_TYPE_FRAMED_USER);
		if (tmp) {
			avl_merge(&request_pairs, &tmp);
		}
	}


	for (i = hints; i; i = i->next) {
		if (matches(request_pairs, name, i, newname) == 0) {
			debug(1, ("matched %s at hints:%d",
				 i->name, i->lineno));
			break;
		}
	}

	if (i == NULL) {
		avl_free(orig_name_pair);
		return 0;
	}
	
	add = avl_dup(i->reply);
	if (orig_name_pair)
		avl_add_pair(&add, orig_name_pair);
	
	/*
	 *	See if we need to adjust the name.
	 */
	if (name_pair) {
		do_strip = 1;
		if ((tmp = avl_find(i->reply, DA_STRIP_USER_NAME)) != NULL ||
		    (tmp = avl_find(i->check, DA_STRIP_USER_NAME)) != NULL)
			do_strip = tmp->lvalue;

		if (do_strip) {
			replace_string(&name_pair->strvalue, newname);
		}

		/* Ok, let's see if we need to further modify the username */
		if ((tmp = avl_find(i->reply, DA_REPLACE_USER_NAME)) != NULL ||
		    (tmp = avl_find(i->check, DA_REPLACE_USER_NAME)) != NULL) {
			char *ptr;
			
			if (!hints_stk_ready) {
				obstack_init(&hints_stk);
				hints_stk_ready = 1;
			}
			ptr = radius_xlate(&hints_stk, tmp->strvalue,
					   request_pairs, NULL);
			if (ptr) 
				replace_string(&name_pair->strvalue, ptr);
			obstack_free(&hints_stk, ptr);
		}
		
		/* Is the rewrite function specified? */
		if ((tmp = avl_find(i->reply, DA_REWRITE_FUNCTION)) != NULL ||
		    (tmp = avl_find(i->check, DA_REWRITE_FUNCTION)) != NULL) {
			if (run_rewrite(tmp->strvalue, request_pairs)) {
				radlog(L_ERR, _("hints:%d: %s(): not defined"),
				       i->lineno,
				       tmp->strvalue);
			}
		}

		debug(1, ("newname is `%s', username is `%s'",
			 newname, name_pair->strvalue));

	}
	
	/* fix-up the string length */
	name_pair->strlength = strlen(name_pair->strvalue);


	/*
	 *	Now add all attributes to the request list,
	 *	except the DA_STRIP_USER_NAME and DA_REPLACE_USER_NAME ones.
	 */
	avl_delete(&add, DA_STRIP_USER_NAME);
	avl_delete(&add, DA_REPLACE_USER_NAME);
	avl_delete(&add, DA_REWRITE_FUNCTION);
	for (last = request_pairs; last && last->next; last = last->next)
		;
	if (last)
		last->next = add;

	return 0;
}

/* ***************************************************************************
 * raddb/huntgroups
 */

/*
 * Compare two pair lists. At least one of the check pairs
 * has to be present in the request.
 */
int
huntgroup_paircmp(request, check)
	VALUE_PAIR *request;
	VALUE_PAIR *check;
{
	VALUE_PAIR *check_item = check;
	VALUE_PAIR *auth_item;
	int result = -1;

	if (check == NULL)
		return 0;

	while (result != 0 && check_item != (VALUE_PAIR *)NULL) {
		if (server_attr(check_item->attribute)) {
			check_item = check_item->next;
			continue;
		}

		debug(20, ("check_item: %A", check_item));

		/*
		 *	See if this item is present in the request.
		 */
		auth_item = request;
		while (auth_item != (VALUE_PAIR *)NULL) {
			debug(30, ("trying %d", auth_item->attribute));
	
			if (check_item->attribute == auth_item->attribute ||
			    ((check_item->attribute == DA_GROUP_NAME ||
			      check_item->attribute == DA_GROUP) &&
			     auth_item->attribute  == DA_USER_NAME))
				break;
			auth_item = auth_item->next;
		}
		if (auth_item == (VALUE_PAIR *)NULL) {
			check_item = check_item->next;
			continue;
		}

		debug(20, ("auth_item: %A", auth_item));

		/*
		 *	OK it is present now compare them.
		 */
	
		switch (check_item->type) {

		case PW_TYPE_STRING:
			switch (check_item->attribute) {
			case DA_NAS_PORT_ID:
				result = portcmp(check_item, auth_item);
				break;
			case DA_GROUP_NAME:
			case DA_GROUP:
				result = groupcmp(request,
						  check_item->strvalue,
						  auth_item->strvalue);
				break;
			case DA_HUNTGROUP_NAME:
				result = !huntgroup_match(request,
							check_item->strvalue);
				break;
			default:
				result = strcmp(check_item->strvalue,
						auth_item->strvalue);
			}
			break;

		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
			if (check_item->lvalue == auth_item->lvalue) {
				result = 0;
			}
			break;
			
		default:
			break;
		}

		debug(20, ("compare: %d", result));

		result = comp_op(check_item->operator, result);
		check_item = check_item->next;
	}

	debug(20, ("returning %d", result));
	return result;

}

/*
 * See if the huntgroup matches.
 */
int
huntgroup_match(request_pairs, huntgroup)
	VALUE_PAIR      *request_pairs;
	char            *huntgroup;
{
	PAIR_LIST *pl;
	
	for (pl = huntgroups; pl; pl = pl->next) {
		if (strcmp(pl->name, huntgroup) != 0)
			continue;
		if (paircmp(request_pairs, pl->check) == 0) {
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
huntgroup_access(radreq)
	RADIUS_REQ *radreq;
{
	VALUE_PAIR      *request_pairs, *pair;
	PAIR_LIST	*pl;
	int		r = 1;

	if (huntgroups == NULL)
		return 1;

	request_pairs = radreq->request;
	for (pl = huntgroups; pl; pl = pl->next) {
		/*
		 *	See if this entry matches.
		 */
		if (paircmp(request_pairs, pl->check) != 0)
			continue;
		debug(1, ("matched huntgroup at huntgroups:%d", pl->lineno));
		r = huntgroup_paircmp(request_pairs, pl->reply) == 0;
		break;
	}

#ifdef DA_REWRITE_FUNCTION
	if (pl &&
	    (pair = avl_find(pl->check, DA_REWRITE_FUNCTION)) != NULL) {
		if (run_rewrite(pair->strvalue, radreq->request)) {
			radlog(L_ERR, _("huntgroups:%d: %s(): not defined"),
			       pl->lineno,
			       pair->strvalue);
		}
	}
#endif	

	debug(1, ("returning %d", r));
	return r;
}

int
read_naslist_file(file)
	char *file;
{
	int rc;
	NAS *nas;
#ifdef USE_SNMP	
	if (master_process()) {
		snmp_init_nas_stat();
	}
#endif
	rc = nas_read_file(file);
	
#ifdef USE_SNMP	
	for (nas = nas_next(NULL); nas; nas = nas_next(nas))
		snmp_attach_nas_stat(nas);
#endif	
	stat_create();
	return rc;
}

/* ***************************************************************************
 * raddb/clients
 */

/*
 * parser
 */
/*ARGSUSED*/
int
read_clients_entry(unused, fc, fv, file, lineno)
	void *unused;
	int fc;
	char **fv;
	char *file;
	int lineno;
{
	CLIENT *cp;
	
	if (fc < 2) {
		radlog(L_ERR, _("%s:%d: too few fields (%d)"),
		       file, lineno, fc);
		return -1;
	}
		
	cp = Alloc_entry(CLIENT);

	cp->ipaddr = get_ipaddr(fv[0]);
	STRING_COPY(cp->secret, fv[1]);
	if (fc == 3)
		STRING_COPY(cp->shortname, fv[2]);
	STRING_COPY(cp->longname, ip_hostname(cp->ipaddr));

	cp->next = clients;
	clients = cp;

	return 0;
}

/*
 * Read the clients file.
 */
int
read_clients_file(file)
	char *file;
{
	free_slist((struct slist*)clients, NULL);
	clients = NULL;

	return read_raddb_file(file, 1, 3, read_clients_entry, NULL);
}


/*
 * Find a client in the CLIENTS list.
 */
CLIENT *
client_lookup_ip(ipaddr)
	UINT4 ipaddr;
{
	CLIENT *cl;

	for(cl = clients; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}


/*
 * Find the name of a client (prefer short name).
 */
char *
client_lookup_name(ipaddr)
	UINT4 ipaddr;
{
	CLIENT *cl;

	if ((cl = client_lookup_ip(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}
	return ip_hostname(ipaddr);
}

/* ****************************************************************************
 * raddb/nastypes
 */

int read_nastypes_entry(void *unused, int fc, char **fv, char *file,
			int lineno);
int read_nastypes_file(char *file);


/*
 * parser
 */
/*ARGSUSED*/
int
read_nastypes_entry(unused, fc, fv, file, lineno)
	void *unused;
	int fc;
	char **fv;
	char *file;
	int lineno;
{
	RADCK_TYPE *mp;
	int method;
		
	if (fc < 2) {
		radlog(L_ERR, _("%s:%d: too few fields"), file, lineno);
		return -1;
	}

	if (strcmp(fv[1], "finger") == 0)
		method = METHOD_FINGER;
	else if (strcmp(fv[1], "snmp") == 0)
		method = METHOD_SNMP;
	else if (strcmp(fv[1], "ext") == 0)
		method = METHOD_EXT;
	else {
		radlog(L_ERR, _("%s:%d: unknown method"), file, lineno);
		return -1;
	}
			
	mp = alloc_entry(sizeof(*mp));
	mp->type = estrdup(fv[0]);
	mp->method = method;
	if (fc == 3)
		mp->args = parse_radck_args(fv[2]);
	else
		mp->args = NULL;
	mp->next = radck_type;
	radck_type = mp;
	return 0;
}
	
int
read_nastypes_file(file)
	char *file;
{
	free_slist((struct slist *)radck_type, free_radck_type);
	radck_type = NULL;
	return read_raddb_file(file, 0, 3, read_nastypes_entry, NULL);
}

RADCK_TYPE *
find_radck_type(name)
	char *name;
{
	RADCK_TYPE *tp;
	
	for (tp = radck_type; tp && strcmp(tp->type, name); tp = tp->next)
		;
	return tp;
}
		

/* ****************************************************************************
 * raddb/realms
 */

/*
 * parser
 */

/* read realms entry */
/*ARGSUSED*/
int
read_realms_entry(unused, fc, fv, file, lineno)
	void *unused;
	int fc;
	char **fv;
	char *file;
	int lineno;
{
	REALM *rp;
	char *p;

	if (fc < 2) {
		radlog(L_ERR, _("%s:%d: too few fields (%d)"),
		       file, lineno, fc);
		return -1;
	}
	
	rp = Alloc_entry(REALM);

	if ((p = strchr(fv[1], ':')) != NULL) {
		*p++ = 0;
		rp->auth_port = atoi(p);
		rp->acct_port = rp->auth_port + 1;
	} else {
		rp->auth_port = auth_port;
		rp->acct_port = acct_port;
	}
	if (strcmp(fv[1], "LOCAL") != 0)
		rp->ipaddr = get_ipaddr(fv[1]);
	STRING_COPY(rp->realm, fv[0]);
	STRING_COPY(rp->server, fv[1]);
	if (fc >= 3) {
		if (strcmp(fv[2], "nostrip") == 0)
			rp->striprealm = 0;
		else if (strcmp(fv[2], "strip") == 0)
			rp->striprealm = 1;
		else {
			radlog(L_ERR, _("%s:%d: invalid flag"),
			       file, lineno);
		}
	}
	if (fc == 4) 
		rp->maxlogins = atoi(fv[3]);
	rp->next = realms;
	realms = rp;
	return 0;
}

/*
 * Read the realms file.
 */
int
read_realms_file(file)
	char *file;
{
	free_slist((struct slist*)realms, NULL);
	realms = NULL;
	
	return read_raddb_file(file, 1, 4, read_realms_entry, NULL);
}

/*
 * Realm Lookup Functions */

/* Find a realm in the REALM list */
REALM *
realm_find(realm)
	char *realm;
{
	REALM *p;

	for (p = realms; p; p = p->next)
		if (strcmp(p->realm, realm) == 0)
			break;
	if (!p) {
		for (p = realms; p; p = p->next)
			if (strcmp(p->realm, "DEFAULT") == 0)
				break;
	}
	return p;
}

/* ****************************************************************************
 * raddb/access.deny
 */

/*
 * parser
 */
void
add_deny(user)
	 char *user;
{
	sym_install(deny_tab, user);
}

/*ARGSUSED*/
int
read_denylist_entry(denycnt, fc, fv, file, lineno)
	int *denycnt;
	int fc;
	char **fv;
	char *file;
	int lineno;
{
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
		symtab_free(deny_tab);
	else
		deny_tab = symtab_create(sizeof(Symbol), 0, NULL);
	denycnt = 0;

	read_raddb_file(name, 0, 1, read_denylist_entry, &denycnt);
	efree(name);
	if (denycnt)
		radlog(L_INFO, _("%d users disabled"), denycnt);
}

/*
 * Return 1 if the given user should be denied access
 */
int
get_deny(user)
	char *user;
{
	return sym_lookup(deny_tab, user) != NULL;
}


/* ***************************************************************************
 * Various utilities, local to this module
 */

/*
 *	See if a VALUE_PAIR list contains Fall-Through = Yes
 */
int
fallthrough(vp)
	VALUE_PAIR *vp;
{
	VALUE_PAIR *tmp;

	return (tmp = avl_find(vp, DA_FALL_THROUGH)) ? tmp->lvalue : 0;
}


/*


/*
 *	Compare a portno with a range.
 */
int
portcmp(check, request)
	VALUE_PAIR *check;
	VALUE_PAIR *request;
{
	char buf[AUTH_STRING_LEN];
	char *s, *p;
	int lo, hi;
	int port = request->lvalue;

	strcpy(buf, check->strvalue);
	s = strtok(buf, ",");
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
		s = strtok(NULL, ",");
	}

	return -1;
}


int
uidcmp(check, username)
	VALUE_PAIR *check;
	char *username;
{
	struct passwd *pwd;

        if ((pwd = getpwnam(username)) == NULL)
                return -1;

	return pwd->pw_uid - check->lvalue;
}

RADIUS_REQ *
auth_request(request_pairs)
	VALUE_PAIR *request_pairs;
{
	VALUE_PAIR *p;

	if (p = avl_find(request_pairs, DA_QUEUE_ID))
		return (RADIUS_REQ*)p->lvalue;
	return NULL;
}

/*
 *	See if user is member of a group.
 *	We also handle additional groups.
 */
int
groupcmp(request, groupname, username)
	VALUE_PAIR *request;
	char *groupname;
	char *username;
{
	struct passwd *pwd;
	struct group *grp;
	char **member;
	int retval;

#ifdef USE_SQL
	RADIUS_REQ *req = auth_request(request);
	if (req && rad_sql_checkgroup(req, groupname) == 0)
		return 0;
#endif

        if ((pwd = getpwnam(username)) == NULL)
                return -1;

	if ((grp = getgrnam(groupname)) == NULL)
		return -1;

	retval = (pwd->pw_gid == grp->gr_gid) ? 0 : -1;
	if (retval < 0) {
		for (member = grp->gr_mem; *member && retval; member++) {
			if (strcmp(*member, pwd->pw_name) == 0)
				retval = 0;
		}
	}
	return retval;
}

/*
 *	Compare prefix/suffix.
 */
int
presufcmp(check, name, rest)
	VALUE_PAIR *check;
	char *name;
	char *rest;
{
	int len, namelen;
	int ret = -1;

	debug(1, ("comparing %s and %s, check->attr is %d",
		 name, check->strvalue, check->attribute));

	len = strlen(check->strvalue);
	switch (check->attribute) {
		case DA_PREFIX:
			ret = strncmp(name, check->strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case DA_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len, check->strvalue);
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
	DA_PASSWORD,
	DA_CRYPT_PASSWORD,
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
	DA_AUTH_DATA,
	DA_QUEUE_ID
};

int
server_attr(attr)
	int attr;
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
paircmp(request, check)
	VALUE_PAIR *request;
	VALUE_PAIR *check;
{
	VALUE_PAIR *check_item = check;
	VALUE_PAIR *auth_item;
	char username[AUTH_STRING_LEN];
	int result = 0;
	int compare;

	while (result == 0 && check_item != NULL) {
		if (server_attr(check_item->attribute)) {  
			check_item = check_item->next;
			continue;
		}
		debug(20, ("check_item: %A", check_item));

		/*
		 *	See if this item is present in the request.
		 */
		for (auth_item = request; auth_item; 
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
				if (strcmp(check_item->strvalue,
					   auth_item->strvalue) != 0)
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

		debug(20, ("auth_item: %A", auth_item));

		/*
		 *	OK it is present now compare them.
		 */
		
		compare = 0;	/* default result */
		switch (check_item->type) {
		case PW_TYPE_STRING:
			switch (check_item->attribute) {
			case DA_PREFIX:
			case DA_SUFFIX:
				strcpy(username, auth_item->strvalue);
				compare = presufcmp(check_item,
						    auth_item->strvalue,
						    username);
				break;
			case DA_NAS_PORT_ID:
				compare = portcmp(check_item, auth_item);
				break;
			case DA_GROUP_NAME:
			case DA_GROUP:
				strcpy(username, auth_item->strvalue);
				compare = groupcmp(request,
						   check_item->strvalue,
						   username);
				break;
			case DA_HUNTGROUP_NAME:
				compare = !huntgroup_match(request,
							 check_item->strvalue);
				break;
			default:
				compare = strcmp(auth_item->strvalue,
						 check_item->strvalue);
			}
			break;

		case PW_TYPE_INTEGER:
			switch (check_item->attribute) {
			case DA_USER_UID:
				compare = uidcmp(check_item, username);
				break;
			}
			/*FALLTHRU*/
		case PW_TYPE_IPADDR:
			compare = auth_item->lvalue - check_item->lvalue;
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
 * Free a PAIR_LIST
 */
void
pairlist_free(pl)
	PAIR_LIST **pl;
{
	PAIR_LIST *p, *next;

	for (p = *pl; p; p = next) {
		if (p->name)
			efree(p->name);
		if (p->check)
			avl_free(p->check);
		if (p->reply)
			avl_free(p->reply);
		next = p->next;
		free_entry(p);
	}
	*pl = NULL;
}

int
hints_pairmatch(pl, req, name, ret_name)
	PAIR_LIST *pl;
	VALUE_PAIR *req;
	char *name;
	char *ret_name;
{
	VALUE_PAIR *pair;
	char username[AUTH_STRING_LEN];
	int compare;
	
	strcpy(ret_name, name);
	strncpy(username, name, AUTH_STRING_LEN);

	compare = 0;
	for (pair = pl->check; compare == 0 && pair; pair = pair->next) {
		switch (pair->attribute) {
		case DA_PREFIX:
		case DA_SUFFIX:
			compare = presufcmp(pair, username, ret_name);
			strncpy(username, ret_name, AUTH_STRING_LEN);
			break;
		case DA_USER_UID:
			compare = uidcmp(pair, username);
			break;
		case DA_GROUP:
			compare = groupcmp(req, pair->strvalue, username);
			break;
		default:
			continue;
		}
		compare = comp_op(pair->operator, compare);
	}

	return compare;
}

/* ***************************************************************************
 * a *very* restricted version  of wildmat
 */
char *
wild_start(str)
	char *str;
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
match_any_chars(expr, name)
	char **expr;
	char **name;
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
wild_match(expr, name, return_name)
	char *expr;
	char *name;
	char *return_name;
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
	return 0;
}

/* ************************************************************************* */

/*
 * Match a username with a wildcard expression.
 */
int
matches(req, name, pl, matchpart)
	VALUE_PAIR *req;
	char *name;
	PAIR_LIST *pl;
	char *matchpart;
{
	if (strncmp(pl->name, "DEFAULT", 7) == 0 ||
	    wild_match(pl->name, name, matchpart) == 0)
		return hints_pairmatch(pl, req, name, matchpart);
	return 1;
}	
	
/* ****************************************************************************
 * Read all configuration files
 */

#if USE_DBM
/*
 *	See if a potential DBM file is present.
 */
static int checkdbm(char *users, char *ext);

int
checkdbm(users, ext)
	char *users;
	char *ext;
{
	char buffer[256];
	struct stat st;

	strcpy(buffer, users);
	strcat(buffer, ext);

	return stat(buffer, &st);
}
#endif


static int reload_data(enum reload_what what, int *do_radck);

int
reload_data(what, do_radck)
	enum reload_what what;
	int *do_radck;
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
		symtab_free(user_tab);
		path = mkfilename(radius_dir, RADIUS_USERS);
	
#if USE_DBM
		if (use_dbm) {
			if (access(path, 0) == 0) {
				radlog(L_WARN,
				       _("using only dbm: USERS NOT LOADED"));
			}
		} else {
			if (checkdbm(path, ".dir") == 0 ||
			    checkdbm(path, ".db") == 0)
				radlog(L_WARN,
		    _("DBM files found but no -b flag given - NOT using DBM"));
	        
#endif
		if (read_users(path)) {
			radlog(L_CRIT, _("can't load %s: exited"), path);
			exit(1);
		} else
			radlog(L_INFO, _("%s reloaded."), path);
#if USE_DBM
		}
#endif
		efree(path);
		*do_radck = 1;
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
		pairlist_free(&huntgroups);
		path = mkfilename(radius_dir, RADIUS_HUNTGROUPS);
		huntgroups = file_read(path);
		efree(path);
		break;
		
	case reload_hints:
		pairlist_free(&hints);
		path = mkfilename(radius_dir, RADIUS_HINTS);
		hints = file_read(path);
		efree(path);
		if (!use_dbm) 
			*do_radck = 1;
		break;
		
	case reload_clients:
		path = mkfilename(radius_dir, RADIUS_CLIENTS);
		if (read_clients_file(path) < 0)
			rc = 1;
		proxy_cleanup();
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
		if (read_realms_file(path) < 0)
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
		rc = parse_rewrite();
		break;
		
	default:
		radlog(L_CRIT, _("INTERNAL ERROR: unknown reload code: %d"),
		       what);
	}
		
	return rc;
}

int
reload_config_file(what)
	enum reload_what what;
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
static void dump_pair_list(FILE *fp, char *header, PAIR_LIST *pl);

void
dump_pairs(fp, pair)
	FILE       *fp;
	VALUE_PAIR *pair;
{
	int etype;
	
	for (; pair; pair = pair->next) {
		fprintf(fp, "\t\t%s %s ", pair->name, 
			op_tab[pair->operator].name);

		switch (pair->type) {
		case PW_TYPE_STRING:
			fprintf(fp, "(STRING) ");
			break;

		case PW_TYPE_INTEGER:
			fprintf(fp, "(INTEGER) ");
			break;

		case PW_TYPE_IPADDR:
			fprintf(fp, "(IP) ");
			break;
		
		case PW_TYPE_DATE:
			fprintf(fp, "(DATE) ");
			break;
			
		default:
			fprintf(fp, "(%d) ", pair->type);
		}

		if (pair->eval) {
			etype = PW_TYPE_STRING;
			fprintf(fp, "=");
		} else
			etype = pair->type;
		
		switch (etype) {
		case PW_TYPE_STRING:
			fprintf(fp, "%s", pair->strvalue);
			break;

		case PW_TYPE_INTEGER:
			fprintf(fp, "%ld", pair->lvalue);
			break;

		case PW_TYPE_IPADDR:
			fprintf(fp, "%lx", pair->lvalue);
			break;
		
		case PW_TYPE_DATE:
			fprintf(fp, "%ld", pair->lvalue);
			break;
			
		}
		fprintf(fp, "\n");
	}
}

void
dump_pair_list(fp, header, pl)
	FILE      *fp;
	char      *header;
	PAIR_LIST *pl;
{
	fprintf(fp, "%s {\n", header);
	for ( ; pl; pl = pl->next) {
		fprintf(fp, "\t%s:\n", pl->name);
		fprintf(fp, "\tcheck {\n");
		dump_pairs(fp, pl->check);
		fprintf(fp, "\t}\n");

		fprintf(fp, "\treply {\n");
		dump_pairs(fp, pl->reply);
		fprintf(fp, "\t}\n");
	}
	fprintf(fp, "}\n");
}

void
dump_users_db()
{
	FILE *fp;
	int i;
	User_symbol *sym;
	char *name = mkfilename(radlog_dir, RADIUS_DUMPDB_NAME);
	
	fp = fopen(name, "w");
	if (!fp) {
		radlog(L_ERR, _("can't create parser output file `%s': %s"),
		    RADIUS_DUMPDB_NAME,
		    strerror(errno));
		efree(name);
		return;
	}

	fchmod(fileno(fp), S_IRUSR|S_IWUSR);

	fprintf(fp, "%s {\n", "users");
	for (i = 0; i < user_tab->hashsize; i++) {
		for (sym = (User_symbol*)user_tab->sym[i]; sym;
		     sym = (User_symbol*)sym->next) {
			fprintf(fp, "\t%s:\n", sym->name);
			fprintf(fp, "\tcheck {\n");
			dump_pairs(fp, sym->check);
			fprintf(fp, "\t}\n");

			fprintf(fp, "\treply {\n");
			dump_pairs(fp, sym->reply);
			fprintf(fp, "\t}\n");
		}
	}
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

/*
 * Strip a username, based on Prefix/Suffix from the "users" file.
 * Not 100% safe, since we don't compare attributes.
 */
void
presuf_setup(request_pairs)
	VALUE_PAIR *request_pairs;
{
	User_symbol *sym;
	USER_LOOKUP lu;
	VALUE_PAIR  *presuf_pair;
	VALUE_PAIR  *name_pair;
	VALUE_PAIR  *tmp;
	char	     name[RUT_NAMESIZE+1];
	
	if ((name_pair = avl_find(request_pairs, DA_USER_NAME)) == NULL)
		return ;

	for (sym = user_lookup(name_pair->strvalue, &lu); sym;
	     sym = user_next(&lu)) {

		if ((presuf_pair = avl_find(sym->check, DA_PREFIX)) == NULL &&
		    (presuf_pair = avl_find(sym->check, DA_SUFFIX)) == NULL)
			continue;
		if (presufcmp(presuf_pair, name_pair->strvalue, name) != 0)
			continue;
		/*
		 *	See if username must be stripped.
		 */
		if ((tmp = avl_find(sym->check, DA_STRIP_USER_NAME)) != NULL &&
		    tmp->lvalue == 0)
			continue;
		replace_string(&name_pair->strvalue, name);
		name_pair->strlength = strlen(name_pair->strvalue);
		break;
	}
}

void
strip_username(do_strip, name, check_item, stripped_name)
	int         do_strip;
	char        *name;
	VALUE_PAIR  *check_item;
	char        *stripped_name;
{
	char tmpname[AUTH_STRING_LEN];
	char *source_ptr = name;
	VALUE_PAIR *presuf_item, *tmp;
	
	/*
	 *	See if there was a Prefix or Suffix included.
	 */
	if ((presuf_item = avl_find(check_item, DA_PREFIX)) == NULL)
		presuf_item = avl_find(check_item, DA_SUFFIX);
	if (presuf_item) {
		if (tmp = avl_find(check_item, DA_STRIP_USER_NAME))
			do_strip = tmp->lvalue;
		if (do_strip) { 
			if (presufcmp(presuf_item, name, tmpname) == 0)
				source_ptr = tmpname;
		}
	}
		
	strcpy(stripped_name, source_ptr);
}


















