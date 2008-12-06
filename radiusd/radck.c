/* This file is part of GNU Radius.
   Copyright (C) 2001,2003,2004,2007,2008 Free Software Foundation, Inc.

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
#include <limits.h>

#include <radiusd.h>
#include <rewrite.h>

#ifndef CHAR_BIT
# define CHAR_BIT 8
#endif
#define BITS_PER_WORD   (sizeof(unsigned)*CHAR_BIT)
#define MAXTABLE        32767

#define WORDSIZE(n)     (((n) + BITS_PER_WORD - 1) / BITS_PER_WORD)
#define SETBIT(x, i)    ((x)[(i)/BITS_PER_WORD] |= (1<<((i) % BITS_PER_WORD)))
#define RESETBIT(x, i)  ((x)[(i)/BITS_PER_WORD] &= ~(1<<((i) % BITS_PER_WORD)))
#define BITISSET(x, i)  (((x)[(i)/BITS_PER_WORD] & (1<<((i) % BITS_PER_WORD))) != 0)

struct check_datum {
        grad_symtab_t   *symtab;
        unsigned count;    /* Number of elements */
        unsigned rlen;     /* Number of elements in a row */
        unsigned *r;
};

static void TC(unsigned *R, int n);
static void mark_profile(struct check_datum *datum, User_symbol *sym,
                         char *target_name);
static void mark_list(struct check_datum *datum, User_symbol *sym, 
                      grad_avp_t *list);
static void check_dup_attr(grad_avp_t **prev, grad_avp_t *ptr, grad_locus_t *loc);


static int
sym_counter(void *closure, grad_symbol_t *symbol)
{
	User_symbol *sym = (User_symbol *) symbol;

        sym->ordnum = (*(int*)closure)++;
        return 0;
}

static void
radck_setbit(unsigned *r, unsigned rowsize, unsigned row, unsigned col)
{
        SETBIT(r + rowsize * row, col);
}

static int
radck_bitisset(unsigned *r, unsigned rowsize, unsigned row, unsigned col)
{
        return BITISSET(r + rowsize * row, col);
}

static void
mark_profile(struct check_datum *datum, User_symbol *sym, char *target_name)
{
        User_symbol *target = (User_symbol*)grad_sym_lookup(datum->symtab, target_name);

        if (!target) {
                grad_log_loc(GRAD_LOG_ERR, &sym->loc,
			     _("Match-Profile refers to non-existing profile (%s)"),
			     target_name);
                return;
        }
        
        do {
                radck_setbit(datum->r, datum->rlen, sym->ordnum,
			     target->ordnum);
        } while ((target = target->next) &&
                 !strcmp(target->name, target_name));
}

static void
mark_list(struct check_datum *datum, User_symbol *sym, grad_avp_t *list)
{
        grad_avp_t *p;

        if (p = grad_avl_find(list, DA_MATCH_PROFILE)) {
                do {
                        mark_profile(datum, sym, p->avp_strvalue);
                } while (p->next &&
                         (p = grad_avl_find(p->next, DA_MATCH_PROFILE)));
        }
}

static int
pass1(void *closure, grad_symbol_t *symbol)
{
	struct check_datum *datum = closure;
	User_symbol *sym = (User_symbol *) symbol;

        mark_list(datum, sym, sym->check);
        mark_list(datum, sym, sym->reply);
        return 0;
}

static int
pass2(void *closure, grad_symbol_t *symbol)
{
	struct check_datum *datum = closure;
	User_symbol *sym = (User_symbol *) symbol;

        if (radck_bitisset(datum->r, datum->rlen, sym->ordnum, sym->ordnum)) {
                grad_log_loc(GRAD_LOG_ERR, &sym->loc,
			     _("circular dependency for %s"),
			     sym->name);
                grad_symtab_delete(datum->symtab, (grad_symbol_t *)sym);
                datum->count--;
        }
        return 0;
}

void
radck()
{
        int user_count;
        struct check_datum datum;
        unsigned *r, size;
        
        /*
         * Count users.
         */
        user_count = 0;
        grad_symtab_iterate(user_tab, sym_counter, &user_count);

        if (user_count) {
		/* Allocate matrix */
		size = (user_count + BITS_PER_WORD - 1) / BITS_PER_WORD;
		r = grad_malloc(user_count*size*sizeof(unsigned));
		if (!r) {
			grad_log(GRAD_LOG_ERR,
			         _("not enough memory for transitivity check"));
			return;
		}

		/* Initialize array */
		datum.symtab = user_tab;
		datum.count  = user_count;
		datum.rlen   = size;
		datum.r      = r;
		
		/* First pass: mark directly connected entries */
		grad_symtab_iterate(user_tab, pass1, &datum);

		/* Compute transitive closure of the matrix r */
		TC(datum.r, user_count);

		/* Select all non-zero diagonal elements and delete
		   corresponding profiles  */
		grad_symtab_iterate(user_tab, pass2, &datum);
		grad_free(datum.r);

		user_count = datum.count;
	}
	
        if (user_count == 0) 
                grad_log(GRAD_LOG_ERR, _("USER LIST IS EMPTY"));
}

static void
check_dup_attr(grad_avp_t **prev, grad_avp_t *ptr, grad_locus_t *loc)
{
        if (*prev) {
                grad_log_loc(GRAD_LOG_WARN, loc,
			     _("duplicate %s attribute"), ptr->name);
        } else
                *prev = ptr;
}

static int
compile_pair(grad_avp_t *pair)
{
	if (pair->eval_type == grad_eval_interpret) {
		char *symname = rewrite_compile(pair->avp_strvalue);
		if (symname == 0) 
			return -1;
		pair->eval_type = grad_eval_compiled;
		grad_free(pair->avp_strvalue);
		pair->avp_strvalue = symname;
		pair->avp_strlength = strlen(symname);
	}
	return 0;
}

/*ARGSUSED*/
int
fix_check_pairs(int cf_file, grad_locus_t *loc, char *name, grad_avp_t **pairs)
{
        grad_avp_t *p;
        grad_avp_t *auth_type = NULL;
        grad_avp_t *auth_data = NULL;
        grad_avp_t *pam_auth = NULL;
        grad_avp_t *password = NULL;
        grad_avp_t *crypt_password = NULL;
        grad_avp_t *chap_password = NULL;
        grad_avp_t *pass_loc = NULL;
        grad_dict_attr_t *dict;
        int errcnt = 0;
        
        for (p = *pairs; p; p = p->next) {
                
                dict = grad_attr_number_to_dict(p->attribute);
                if (dict) {
                        if (!(dict->prop & GRAD_AF_LHS(cf_file))) {
                                grad_log_loc(GRAD_LOG_ERR, loc,
					 _("attribute %s not allowed in LHS"),
					     dict->name);
                                errcnt++;
                                continue;
                        }
                }

                /* Specific attribute checks */
                switch (p->attribute) {
                case DA_AUTH_TYPE:
                        check_dup_attr(&auth_type, p, loc);
                        break;
                        
                case DA_AUTH_DATA:
                        check_dup_attr(&auth_data, p, loc);
                        break;
                        
                case DA_PAM_AUTH:
                        check_dup_attr(&pam_auth, p, loc);
                        break;

                case DA_USER_PASSWORD:
                        check_dup_attr(&password, p, loc);
                        break;

                case DA_CRYPT_PASSWORD:
                        check_dup_attr(&crypt_password, p, loc);
                        break;
                        
                case DA_PASSWORD_LOCATION:
			if (p->avp_lvalue == DV_PASSWORD_LOCATION_SQL) {
				const char *msg;
				if (!sql_auth_avail_p(&msg)) {
					grad_log_loc(GRAD_LOG_ERR, loc, "%s", msg);
					errcnt++;
				}
			}
                        check_dup_attr(&pass_loc, p, loc);
                        break;

                case DA_CHAP_PASSWORD:
                        check_dup_attr(&chap_password, p, loc);
                        break;

                case DA_MATCH_PROFILE:
                        if (strncmp(p->avp_strvalue, "DEFAULT", 7) == 0 ||
                            strncmp(p->avp_strvalue, "BEGIN", 5) == 0) {
                                grad_log_loc(GRAD_LOG_ERR, loc,
					     "%s",
				  _("Match-Profile refers to a DEFAULT entry"));
                                errcnt++;
                        }
                        break;

		case DA_SIMULTANEOUS_USE:
			if (!radius_mlc_enabled_p()) {
				grad_log_loc(GRAD_LOG_ERR, loc,
					     "%s",
					     _("Simultaneous-Use is used, but multiple login checking is not enabled"));
				errcnt++;
			}
                }
        }

        if (cf_file != GRAD_CF_USERS)
                return 0;

        /*
         * Now let's check what we've got
         */
        if (!auth_type) {
                int type;
                
                if (crypt_password) {
                        type = DV_AUTH_TYPE_CRYPT_LOCAL;
                        crypt_password->attribute = DA_USER_PASSWORD;
                } else if (password) {
                        if (!strcmp(password->avp_strvalue, "UNIX"))
                                type = DV_AUTH_TYPE_SYSTEM;
                        else if (!strcmp(password->avp_strvalue, "PAM"))
                                type = DV_AUTH_TYPE_PAM;
                        else if (!strcmp(password->avp_strvalue, "MYSQL")
                                 || !strcmp(password->avp_strvalue, "SQL"))
                                type = DV_AUTH_TYPE_SQL;
                        else
                                type = DV_AUTH_TYPE_LOCAL;
                } else {
                        return 0;
                }
                auth_type = grad_avp_create_integer(DA_AUTH_TYPE, type);
                grad_avl_add_pair(pairs, auth_type);
        }
        
        switch (auth_type->avp_lvalue) {
        case DV_AUTH_TYPE_LOCAL:
                if (!password && !chap_password && !pass_loc) {
                        grad_log_loc(GRAD_LOG_ERR, loc,
				     "%s",
				     _("No User-Password attribute in LHS"));
                        errcnt++;
                }
                break;
                
        case DV_AUTH_TYPE_SYSTEM:
		if (radiusd_user.username) {
			grad_log_loc(GRAD_LOG_ERR, loc,
				     _("Auth-Type = System can only be used when running with root privileges"));
			errcnt++;
		}
		/*FALLTHROUGH*/
		
        case DV_AUTH_TYPE_REJECT:
        case DV_AUTH_TYPE_ACCEPT:
                if (password) {
                        grad_log_loc(GRAD_LOG_WARN, loc,
				     "%s",
			       _("User-Password attribute ignored for this Auth-Type"));
                }
                if (pass_loc) {
                        grad_log_loc(GRAD_LOG_WARN, loc,
				     "%s",
			       _("Password-Location attribute ignored for this Auth-Type"));
                }
                break;
                
        case DV_AUTH_TYPE_CRYPT_LOCAL:
                if (!password && !crypt_password && !pass_loc) {
                        grad_log_loc(GRAD_LOG_ERR, loc,
				     "%s",
			       _("No User-Password attribute in LHS"));
                        errcnt++;
                }
                break;

        case DV_AUTH_TYPE_SECURID:
                grad_log_loc(GRAD_LOG_ERR, loc,
			     "%s",
			   _("Authentication type not supported"));
                errcnt++;
                break;
                
        case DV_AUTH_TYPE_SQL:
	{
		const char *msg;
		if (!sql_auth_avail_p(&msg)) {
			grad_log_loc(GRAD_LOG_ERR, loc, "%s", msg);
			errcnt++;
			break;
		}
		
                if (password || crypt_password) {
                        grad_log_loc(GRAD_LOG_WARN, loc,
				     "%s",
			       _("User-Password attribute ignored for this Auth-Type"));
                }

                grad_avl_delete(pairs, DA_AUTH_TYPE);
                p = grad_avp_create_integer(DA_AUTH_TYPE, 
					    DV_AUTH_TYPE_CRYPT_LOCAL);
                grad_avl_add_pair(pairs, p);
                
                p = grad_avp_create_integer(DA_PASSWORD_LOCATION, 
					    DV_PASSWORD_LOCATION_SQL);
                grad_avl_add_pair(pairs, p);
                
                break;
	}
	
        case DV_AUTH_TYPE_PAM:
                if (pam_auth && auth_data) {
                        grad_log_loc(GRAD_LOG_WARN, loc,
			             "%s",
			       _("Both Auth-Data and PAM-Auth attributes present"));
                        auth_data = NULL;
                } else 
                        pam_auth = auth_data = NULL;
                break;
        }
        
        return errcnt;
}

int
fix_reply_pairs(int cf_file, grad_locus_t *loc, char *name, grad_avp_t **pairs)
{
        grad_avp_t *p;
        int fall_through = 0;
        grad_dict_attr_t *dict;
        int errcnt = 0;
        
        for (p = *pairs; p; p = p->next) {
                dict = grad_attr_number_to_dict(p->attribute);
                if (dict) {
                        if (!(dict->prop & GRAD_AF_RHS(cf_file))) {
                                grad_log_loc(GRAD_LOG_ERR, loc,
					  _("attribute %s not allowed in RHS"),
					     dict->name);
                                errcnt++;
                                continue;
                        }
                }

                /* Specific attribute checks */
                switch (p->attribute) {
                case DA_FALL_THROUGH:
                        fall_through++;
                        break;

		case DA_ADD_PORT_TO_IP_ADDRESS:
			grad_log_loc(GRAD_LOG_ERR, loc,
			     _("Use of Add-Port-To-IP-Address is deprecated"));
			errcnt++;
                }

		if (compile_pair(p))
			errcnt++;
        }

        if (strncmp(name, "BEGIN", 5) == 0 && fall_through == 0) {
                grad_log_loc(GRAD_LOG_WARN, loc, "%s", _("BEGIN without Fall-Through"));
        }
        return errcnt;
}

/* given n by n matrix of bits R, modify its contents
   to be the transitive closure of what was given.  */

void
TC(unsigned *R, int n)
{
        register int rowsize;
        register unsigned mask;
        register unsigned *rowj;
        register unsigned *rp;
        register unsigned *rend;
        register unsigned *ccol;

        unsigned *relend;
        unsigned *cword;
        unsigned *rowi;

        rowsize = WORDSIZE(n) * sizeof(unsigned);
        relend = (unsigned *) ((char *) R + (n * rowsize));

        cword = R;
        mask = 1;
        rowi = R;
        while (rowi < relend) {
                ccol = cword;
                rowj = R;
                
                while (rowj < relend) {
                        if (*ccol & mask) {
                                rp = rowi;
                                rend = (unsigned *) ((char *) rowj + rowsize);
                                
                                while (rowj < rend)
                                        *rowj++ |= *rp++;
                        } else {
                                rowj = (unsigned *) ((char *) rowj + rowsize);
                        }
                        
                        ccol = (unsigned *) ((char *) ccol + rowsize);
                }
                
                mask <<= 1;
                if (mask == 0) {
                        mask = 1;
                        cword++;
                }
                rowi = (unsigned *) ((char *) rowi + rowsize);
        }
}
