/* This file is part of GNU Radius.
   Copyright (C) 2001,2003 Sergey Poznyakoff
  
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
#include <limits.h>
#include <symtab.h>
#include <radiusd.h>
#include <parser.h>
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
        Symtab   *symtab;
        unsigned count;    /* Number of elements */
        unsigned rlen;     /* Number of elements in a row */
        unsigned *r;
};

static void TC(unsigned *R, int n);
static int sym_counter(void *closure, User_symbol *sym);
static void mark_profile(struct check_datum *datum, User_symbol *sym,
                         char *target_name);
static void mark_list(struct check_datum *datum, User_symbol *sym, 
                      VALUE_PAIR *list);
static int pass1(struct check_datum *datum, User_symbol *sym);
static int pass2(struct check_datum *datum, User_symbol *sym);
static void check_dup_attr(VALUE_PAIR **prev, VALUE_PAIR *ptr, int line);


int
sym_counter(void *closure, User_symbol *sym)
{
        sym->ordnum = (*(int*)closure)++;
        return 0;
}

void
radck_setbit(unsigned *r, unsigned rowsize, unsigned row, unsigned col)
{
        SETBIT(r + rowsize * row, col);
}

int
radck_bitisset(unsigned *r, unsigned rowsize, unsigned row, unsigned col)
{
        return BITISSET(r + rowsize * row, col);
}

void
mark_profile(struct check_datum *datum, User_symbol *sym, char *target_name)
{
        User_symbol *target = (User_symbol*)sym_lookup(datum->symtab, target_name);

        if (!target) {
                radlog(L_ERR,
                       _("users:%d: Match-Profile refers to non-existing profile (%s)"),
                       sym->lineno, target_name);
                return;
        }
        
        do {
                radck_setbit(datum->r, datum->rlen, sym->ordnum,
			     target->ordnum);
        } while ((target = target->next) &&
                 !strcmp(target->name, target_name));
}

void
mark_list(struct check_datum *datum, User_symbol *sym, VALUE_PAIR *list)
{
        VALUE_PAIR *p;

        if (p = avl_find(list, DA_MATCH_PROFILE)) {
                do {
                        mark_profile(datum, sym, p->avp_strvalue);
                } while (p->next &&
                         (p = avl_find(p->next, DA_MATCH_PROFILE)));
        }
}

static int
compile_pairs(VALUE_PAIR *pair)
{
	for (; pair; pair = pair->next) {
		if (pair->eval_type == eval_interpret) {
			char *symname = rewrite_compile(pair->avp_strvalue);
			if (symname == 0) 
				return -1;
			pair->eval_type = eval_compiled;
			efree(pair->avp_strvalue);
			pair->avp_strvalue = symname;
			pair->avp_strlength = strlen(symname);
		}
	}
	return 0;
}

int
pass1(struct check_datum *datum, User_symbol *sym)
{
	if (compile_pairs(sym->reply)) {
                radlog(L_ERR,
                       _("users:%d: discarding entry %s"),
                       sym->lineno, sym->name);
                symtab_delete(datum->symtab, (Symbol *)sym);
                datum->count--;
	}
        mark_list(datum, sym, sym->check);
        mark_list(datum, sym, sym->reply);
        return 0;
}

int
pass2(struct check_datum *datum, User_symbol *sym)
{
        if (radck_bitisset(datum->r, datum->rlen, sym->ordnum, sym->ordnum)) {
                radlog(L_ERR,
                       _("users:%d: circular dependency for %s"),
                       sym->lineno, sym->name);
                symtab_delete(datum->symtab, (Symbol *)sym);
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
        symtab_iterate(user_tab, sym_counter, &user_count);

        if (user_count) {
		/* Allocate matrix */
		size = (user_count + BITS_PER_WORD - 1) / BITS_PER_WORD;
		r = radxmalloc(user_count*size*sizeof(unsigned));
		if (!r) {
			radlog(L_ERR,
			       _("not enough memory for transitivity check"));
			return;
		}

		/* Initialize array */
		datum.symtab = user_tab;
		datum.count  = user_count;
		datum.rlen   = size;
		datum.r      = r;
		
		/* First pass: mark directly connected entries */
		symtab_iterate(user_tab, pass1, &datum);

		/* Compute transitive closure of the matrix r */
		TC(datum.r, user_count);

		/* Select all non-zero diagonal elements and delete
		   corresponding profiles  */
		symtab_iterate(user_tab, pass2, &datum);
		efree(datum.r);

		user_count = datum.count;
	}
	
        if (user_count == 0) 
                radlog(L_ERR, _("USER LIST IS EMPTY"));
}

void
check_dup_attr(VALUE_PAIR **prev, VALUE_PAIR *ptr, int line)
{
        if (*prev) {
                radlog(L_WARN,
                       _("users:%d: duplicate %s attribute"),
                       line, ptr->name);
        } else
                *prev = ptr;
}

/*ARGSUSED*/
int
fix_check_pairs(int cf_file, char *filename, int line, char *name,
                VALUE_PAIR **pairs)
{
        VALUE_PAIR *p;
        VALUE_PAIR *auth_type = NULL;
        VALUE_PAIR *auth_data = NULL;
        VALUE_PAIR *pam_auth = NULL;
        VALUE_PAIR *password = NULL;
        VALUE_PAIR *crypt_password = NULL;
        VALUE_PAIR *chap_password = NULL;
        VALUE_PAIR *pass_loc = NULL;
        DICT_ATTR *dict;
        int errcnt = 0;
        
        for (p = *pairs; p; p = p->next) {
                
                dict = attr_number_to_dict(p->attribute);
                if (dict) {
                        if (!(dict->prop & AF_LHS(cf_file))) {
                                radlog(L_ERR,
                        _("%s:%d: attribute %s not allowed in LHS"),
                                       filename, line, dict->name);
                                errcnt++;
                                continue;
                        }
                }

                /* Specific attribute checks */
                switch (p->attribute) {
                case DA_AUTH_TYPE:
                        check_dup_attr(&auth_type, p, line);
                        break;
                        
                case DA_AUTH_DATA:
                        check_dup_attr(&auth_data, p, line);
                        break;
                        
                case DA_PAM_AUTH:
                        check_dup_attr(&pam_auth, p, line);
                        break;

                case DA_USER_PASSWORD:
                        check_dup_attr(&password, p, line);
                        break;

                case DA_CRYPT_PASSWORD:
                        check_dup_attr(&crypt_password, p, line);
                        break;
                        
                case DA_PASSWORD_LOCATION:
                        check_dup_attr(&pass_loc, p, line);
                        break;

                case DA_CHAP_PASSWORD:
                        check_dup_attr(&chap_password, p, line);
                        break;

                case DA_MATCH_PROFILE:
                        if (strncmp(p->avp_strvalue, "DEFAULT", 7) == 0 ||
                            strncmp(p->avp_strvalue, "BEGIN", 5) == 0) {
                                radlog(L_ERR,
				       "%s:%d: %s",
                                       filename, line,
				       _("Match-Profile refers to a DEFAULT entry"));
                                errcnt++;
                        }
                        break;
                }
                
        }

        if (cf_file != CF_USERS)
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
                                type = DV_AUTH_TYPE_MYSQL;
                        else
                                type = DV_AUTH_TYPE_LOCAL;
                } else {
                        return 0;
                }
                auth_type = avp_create_integer(DA_AUTH_TYPE, type);
                avl_add_pair(pairs, auth_type);
        }
        
        switch (auth_type->avp_lvalue) {
        case DV_AUTH_TYPE_LOCAL:
                if (!password && !chap_password && !pass_loc) {
                        radlog(L_ERR,
			       "%s:%d: %s",
                               filename, line,
			       _("No User-Password attribute in LHS"));
                        errcnt++;
                }
                break;
                
        case DV_AUTH_TYPE_SYSTEM:
        case DV_AUTH_TYPE_REJECT:
        case DV_AUTH_TYPE_ACCEPT:
                if (password) {
                        radlog(L_WARN,
			       "%s:%d: %s",
                               filename, line,
			       _("User-Password attribute ignored for this Auth-Type"));
                }
                if (pass_loc) {
                        radlog(L_WARN,
			       "%s:%d: %s",
			       filename, line,
			       _("Password-Location attribute ignored for this Auth-Type"));
                }
                break;
                
        case DV_AUTH_TYPE_CRYPT_LOCAL:
                if (!password && !crypt_password && !pass_loc) {
                        radlog(L_ERR,
			       "%s:%d: %s",
                               filename, line,
			       _("No User-Password attribute in LHS"));
                        errcnt++;
                }
                break;

        case DV_AUTH_TYPE_SECURID:
                radlog(L_ERR,
                       "%s:%d: %s",
                       filename, line,
		       _("Authentication type not supported"));
                errcnt++;
                break;
                
        case DV_AUTH_TYPE_SQL:
                if (password || crypt_password) {
                        radlog(L_WARN,
			       "%s:%d: %s",
                               filename, line,
			       _("User-Password attribute ignored for this Auth-Type"));
                }

                avl_delete(pairs, DA_AUTH_TYPE);
                p = avp_create_integer(DA_AUTH_TYPE, 
                                       DV_AUTH_TYPE_CRYPT_LOCAL);
                avl_add_pair(pairs, p);
                
                p = avp_create_integer(DA_PASSWORD_LOCATION, 
                                       DV_PASSWORD_LOCATION_SQL);
                avl_add_pair(pairs, p);
                
                break;
                
        case DV_AUTH_TYPE_PAM:
                if (pam_auth && auth_data) {
                        radlog(L_WARN,
			       "%s:%d: %s",
                               filename, line,
			       _("Both Auth-Data and PAM-Auth attributes present"));
                        auth_data = NULL;
                } else 
                        pam_auth = auth_data = NULL;
                break;
        }
        
        return errcnt;
}

int
fix_reply_pairs(int cf_file, char *filename, int line,
                char *name, VALUE_PAIR **pairs)
{
        VALUE_PAIR *p;
        int fall_through = 0;
        DICT_ATTR *dict;
        int errcnt = 0;
        
        for (p = *pairs; p; p = p->next) {
                dict = attr_number_to_dict(p->attribute);
                if (dict) {
                        if (!(dict->prop & AF_RHS(cf_file))) {
                                radlog(L_ERR,
                        _("%s:%d: attribute %s not allowed in RHS"),
                                       filename, line, dict->name);
                                errcnt++;
                                continue;
                        }
                }

                /* Specific attribute checks */
                switch (p->attribute) {
                case DA_FALL_THROUGH:
                        fall_through++;
                        break;
                }
        }

        if (strncmp(name, "BEGIN", 5) == 0 && fall_through == 0) {
                radlog(L_WARN,
                       "%s:%d: %s",
                       filename, line,
		       _("BEGIN without Fall-Through"));
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


