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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <ctype.h>

#include <common.h>

#ifndef DICT_INDEX_SIZE
# define DICT_INDEX_SIZE 2048
#endif

enum dict_symbol_type {
	dict_symbol_uninitialized,
	dict_symbol_attribute,
	dict_symbol_alias
};

typedef struct dict_symbol DICT_SYMBOL;
struct dict_symbol {
        DICT_SYMBOL *next;          /* Link to the next attribute */
	char *name;
	enum dict_symbol_type type; /* Type of the entry */
	union {
		grad_dict_attr_t attr;
		grad_dict_attr_t *alias;
	} v;
};

static grad_symtab_t    *dict_attr_tab;
static grad_dict_attr_t *dict_attr_index[DICT_INDEX_SIZE];
static grad_list_t /* of grad_dict_value_t */ *dictionary_values;
static grad_list_t /* of grad_dict_vendor_t */ *dictionary_vendors;
static int         vendorno;


static grad_dict_attr_t *
dict_symbol_ptr(DICT_SYMBOL *sym)
{
	switch (sym->type) {
	case dict_symbol_uninitialized:
		grad_insist_fail("uninitialized dictionary symbol found!");
		break;
			
	case dict_symbol_attribute:
		return &sym->v.attr;

	case dict_symbol_alias:
		return sym->v.alias;
	}
}

static grad_dict_attr_t *
dict_attr_lookup(char *ident)
{
	DICT_SYMBOL *sym = grad_sym_lookup(dict_attr_tab, ident);
	if (sym) 
		return dict_symbol_ptr(sym);

	return NULL;
}

/* ************************************************************************ */

static int
free_vendor(void *ptr, void *closure ARG_UNUSED)
{
        grad_dict_vendor_t *vp = ptr;
        if (vp->vendorname)
                grad_free(vp->vendorname);
	grad_free(vp);
	return 0;
}

static int
free_value(void *ptr, void *closure ARG_UNUSED)
{
        grad_dict_value_t *vp = ptr;
        grad_free(vp->name);
	grad_free(vp);
	return 0;
}

void
dict_free()
{
        if (dict_attr_tab)
                grad_symtab_clear(dict_attr_tab);
        else
                dict_attr_tab = grad_symtab_create(sizeof(DICT_SYMBOL), NULL);
        memset(dict_attr_index, 0, sizeof dict_attr_index);

	grad_list_destroy(&dictionary_values, free_value, NULL);
        grad_list_destroy(&dictionary_vendors, free_vendor, NULL);
        vendorno = 1;
}

static int
nfields(int fc, int minf, int maxf, grad_locus_t *loc)
{
        if (fc < minf) {
                grad_log_loc(L_ERR, loc, "%s", _("too few fields"));
                return -1;
        } else if (maxf != -1 && fc > maxf) {
                grad_log_loc(L_ERR, loc, "%s", _("too many fields"));
                return -1;
        }
        return 0;
}

/*
 *      Add vendor to the list.
 */
static int
addvendor(char *name, int value)
{
        grad_dict_vendor_t *vval;

        vval = grad_emalloc(sizeof(grad_dict_vendor_t));
        
        vval->vendorname = grad_estrdup(name);
        vval->vendorpec  = value;
        vval->vendorcode = vendorno++;
	if (!dictionary_vendors)
		dictionary_vendors = grad_list_create();
	grad_list_prepend(dictionary_vendors, vval);

        return 0;
}

/* **************************************************************************
   Parser table for built-in abinary attributes
 */

typedef struct attr_parser_tab ATTR_PARSER_TAB;
struct attr_parser_tab {
	ATTR_PARSER_TAB *next;
	int attr;
	attr_parser_fp fun;
};
static ATTR_PARSER_TAB *attr_parser_tab;

static attr_parser_fp
dict_find_parser(int attr)
{
	ATTR_PARSER_TAB *ep;
	for (ep = attr_parser_tab; ep; ep = ep->next)
		if (ep->attr == attr)
			return ep->fun;
	return NULL;
}

void
dict_register_parser(int attr, attr_parser_fp fun)
{
	ATTR_PARSER_TAB *e = grad_emalloc(sizeof(*e));
	e->attr = attr;
	e->fun = fun;
	e->next = attr_parser_tab;
	attr_parser_tab = e;
}

/* **************************************************************************
 * Parser
 */
static int parse_dict(char *name);
	
#define KEYWORD      fv[0]
#define ATTR_NAME    fv[1]
#define ATTR_VALUE   fv[2]
#define ATTR_TYPE    fv[3]
#define ATTR_VENDOR  fv[4]
#define ATTR_FLAGS   fv[5]
#define ATTR_ADDITIVITY fv[6]
#define HAS_VENDOR(c,p)     ((c>=5)&&strcmp(p[4],"-"))
#define HAS_FLAGS(c,p)      (c==6)
#define VALUE_ATTR   fv[1]
#define VALUE_NAME   fv[2]
#define VALUE_NUM    fv[3]
#define VENDOR_NAME  fv[1]
#define VENDOR_VALUE fv[2]

static struct keyword type_kw[] = {
        { "string", TYPE_STRING },
        { "integer", TYPE_INTEGER },
        { "ipaddr", TYPE_IPADDR },
        { "date", TYPE_DATE }
};

/*ARGSUSED*/
static int
_dict_include(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
        if (nfields(fc, 2, 2, loc)) 
                return 0;
        parse_dict(fv[1]);
        return 0;
}

static int
parse_flags(char **ptr, int *flags, grad_locus_t *loc)
{
        int i;
        char *p;
        
        for (p = *ptr+1, i = 0; i < CF_MAX; i++) {
                if (*p == 0) {
                        grad_log_loc(L_ERR, loc, _("missing ]"), *p);
                        return 1;
                }
                switch (*p++) {
                case 'C':
                case 'L':
                        *flags |= AF_LHS(i);
                        break;
                case '-':
                        *flags &= ~AF_LHS(i);
                        break;
                case ']':
                        p--;
                        goto stop;
                default:
                        grad_log_loc(L_ERR, loc,
				     _("invalid syntax flag %c"),
				     p[-1]);
                        return 1;
                }
                switch (*p++) {
                case 'R':
                        *flags |= AF_RHS(i);
                        break;
                case '-':
                        *flags &= ~AF_RHS(i);
                        break;
                default:
                        grad_log_loc(L_ERR, loc,
				     _("invalid syntax flag %c"),
				     p[-1]);
                        return 1;
                }
        }
  stop:
        for (; i < CF_MAX; i++) 
                *flags |= AF_LHS(i)|AF_RHS(i);
        *ptr = p;
        return 0;
}

static int
parse_attr_properties(grad_locus_t *loc, char *str, int *flags, int *prop)
{
	int errcnt = 0;
	char *p;
	
	for (p = str; *p; p++) {
		switch (*p) {
		case 'C':
		case 'L':
			*flags |= AF_LHS(CF_USERS)
				   |AF_LHS(CF_HINTS)
				   |AF_LHS(CF_HUNTGROUPS);
			break;
		case 'R':
			*flags |= AF_RHS(CF_USERS)
				   |AF_RHS(CF_HINTS)
				   |AF_RHS(CF_HUNTGROUPS);
			break;
		case '[':
			if (parse_flags(&p, flags, loc)) {
				while (*++p);
				--p;
				errcnt++;
			}
			break;
		case '=':
			SET_ADDITIVITY(*prop, AP_ADD_REPLACE);
			break;
		case '+':
			SET_ADDITIVITY(*prop, AP_ADD_APPEND);
			break;
		case 'N':
			SET_ADDITIVITY(*prop, AP_ADD_NONE);
			break;
		case 'P':
			*prop |= AP_PROPAGATE;
			break;
		case 'l':
			*flags &= ~AP_INTERNAL;
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			*prop |= AP_USER_FLAG(*p-'0');
			break;
		case 'b':
			*prop |= AP_BINARY_STRING;
			break;
		case 'E':
			*prop |= AP_ENCRYPT_RFC2138;
			break;
		case 'T':
			*prop |= AP_ENCRYPT_RFC2868;
			break;
		case 'c':
			/* Retained for compatibility */
			break;
		default:
			grad_log_loc(L_ERR, loc,
				     _("invalid flag %c"),
				     *p);
			errcnt++;
			break;
		}
	}
	return errcnt;
}

static void
set_default_attr_properties(int value, int *flags, int *prop)
{
        *flags = AF_DEFAULT_FLAGS;
        *prop  = AP_DEFAULT_ADD;

	if (GRAD_VENDOR_CODE(value) == 0) {
		if (value > 255)
			*flags |= AP_INTERNAL;
		/* FIXME: A temporary hack until all users update
		   their dictionaries */
		else if (value == DA_USER_PASSWORD
			 || value == DA_USER_PASSWORD)
			*prop |= AP_ENCRYPT_RFC2138;
	}
}

static int
_dict_attribute(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
	DICT_SYMBOL *sym;
        grad_dict_attr_t *attr;
        int type;
        int vendor = 0;
        unsigned value;
        char *p;
	attr_parser_fp fp = NULL;
        int flags;
        int prop;
        
        if (nfields(fc, 4, 6, loc))
                return 0;
        /*
         * Validate all entries
         */
        
        value = strtol(ATTR_VALUE, &p, 0);
        if (*p) {
                grad_log_loc(L_ERR, loc,
			     _("value not a number (near %s)"),
			     p);
                (*errcnt)++;
                return 0;
        }

	if (strcmp(ATTR_TYPE, "abinary") == 0) {
		type = TYPE_STRING;
		fp = dict_find_parser(value);
		if (!fp) {
			grad_log_loc(L_WARN, loc,
			      _("no parser registered for this attribute"));
			return 0;
		}
	} else
		type = grad_xlat_keyword(type_kw, ATTR_TYPE, TYPE_INVALID);
	
        if (type == TYPE_INVALID) {
                grad_log_loc(L_ERR, loc,
			     "%s",
			     _("invalid type"));
                (*errcnt)++;
                return 0;
        }

        if (HAS_VENDOR(fc, fv)) {
                if ((vendor = grad_vendor_name_to_id(ATTR_VENDOR)) == 0) {
                        grad_log_loc(L_ERR, loc, _("unknown vendor"));
			(*errcnt)++;
                        return 0;
                }
		value |= (vendor << 16);
        } 
	set_default_attr_properties(value, &flags, &prop);

        if (HAS_FLAGS(fc,fv)) {
		int rc = parse_attr_properties(loc, ATTR_FLAGS, &flags, &prop);
		if (rc) {
			++*errcnt;
			return 0;
		}
        }

	sym = grad_sym_lookup_or_install(dict_attr_tab, ATTR_NAME, 1);
	switch (sym->type) {
	case dict_symbol_uninitialized:
		sym->type = dict_symbol_attribute;
		attr = &sym->v.attr;
		break;

	case dict_symbol_attribute:
		grad_log_loc(L_WARN, loc,
			     _("Redefining attribute %s"),
			     ATTR_NAME);
		attr = &sym->v.attr;
		break;
		
	case dict_symbol_alias:
		grad_log_loc(L_WARN, loc,
			     _("Redefining alias %s"),
			     ATTR_NAME);
		attr = sym->v.alias;
	}

	attr->name = sym->name;
        attr->value = value;
        attr->type = type;
        attr->prop = flags | prop;
	attr->parser = fp;
        if (attr->value >= 0 && attr->value < DICT_INDEX_SIZE) 
                dict_attr_index[attr->value] = attr;
        
        return 0;
}

/* Syntax:
   ALIAS oldname newname */
static int
_dict_alias(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
	DICT_SYMBOL *sym;
	grad_dict_attr_t *attr;
	
	if (nfields(fc, 3, 3, loc))
                return 0;

        attr = dict_attr_lookup(fv[1]);
	if (!attr) {
		grad_log_loc(L_ERR, loc,
			     _("Attribute %s is not defined"),
			     fv[1]);
		return 0;
	}
		
	sym = grad_sym_lookup_or_install(dict_attr_tab, fv[2], 1);
	if (sym->type != dict_symbol_uninitialized) {
		grad_log_loc(L_ERR, loc,
			     _("Symbol %s already declared"),
			     fv[2]);
		/*FIXME: location of the previous declaration*/
		/* Not a fatal error: do not increase error count */
		return 0;
	}
	sym->type = dict_symbol_alias;
	sym->v.alias = attr;
	return 0;
}

/* Syntax:
   
   PROPERTY Attribute Flags */
static int
_dict_property(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
	grad_dict_attr_t *attr;
	int i;
	int flags;
	int prop;
	
	if (nfields(fc, 3, -1, loc))
                return 0;

        attr = dict_attr_lookup(fv[1]);
	if (!attr) {
		grad_log_loc(L_ERR, loc,
			     _("Attribute %s is not defined"),
			     fv[1]);
		return 0;
	}

	for (i = 2; i < fc; i++) {
		switch (fv[i][0]) {
		case '+':
			flags = prop = 0;
			if (parse_attr_properties(loc, fv[i]+1,
						  &flags, &prop)) {
				++*errcnt;
				break;
			}
			attr->prop |= flags | prop;
			break;
			
		case '-':
			flags = prop = 0;
			if (parse_attr_properties(loc, fv[i]+1,
						  &flags, &prop)) {
				++*errcnt;
				break;
			}
			attr->prop &= ~(flags | prop);
			break;
			
		default:
			if (i > 2) {
				grad_log_loc(L_ERR, loc,
					     _("PROPERTY syntax error"));
				++*errcnt;
			} else {
				set_default_attr_properties(attr->value,
							    &flags, &prop);
				if (parse_attr_properties(loc, fv[i],
							  &flags, &prop) == 0)
					attr->prop = flags | prop;
				else
					++*errcnt;
				break;
			}
		}
	}
	return 0;
}

static int
_dict_value(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
        grad_dict_value_t *dval;
        grad_dict_attr_t *attr;
        char *p;
        int value;
        
        if (nfields(fc, 4, 4, loc))
                return 0;

        value = strtol(VALUE_NUM, &p, 0);
        if (*p) {
                grad_log_loc(L_ERR, loc,
			     _("value not a number (near %s)"),
			     p);
                (*errcnt)++;
                return 0;
        }

        attr = dict_attr_lookup(VALUE_ATTR);
	if (!attr) {
		grad_log_loc(L_ERR, loc,
			     _("Attribute %s is not defined"),
			     VALUE_ATTR);
                (*errcnt)++;
		return 0;
	}

	attr->prop |= AP_TRANSLATE;
	
        /* Create a new VALUE entry for the list */
        dval = grad_emalloc(sizeof(grad_dict_value_t));
                        
        dval->name = grad_estrdup(VALUE_NAME);
        dval->attr = attr;
        dval->value = value;

        /* Append */
	if (!dictionary_values)
		dictionary_values = grad_list_create();
	grad_list_append(dictionary_values, dval);
        
        return 0;
}

static int
_dict_vendor(int *errcnt, int fc, char **fv, grad_locus_t *loc)
{
        int value;
        char *p;

        if (nfields(fc, 3, 3, loc))
                return 0;

        value = strtol(VENDOR_VALUE, &p, 0);
        if (*p) {
                grad_log_loc(L_ERR, loc,
			     _("value not a number (near %s)"),
			     p);
                (*errcnt)++;
                return 0;
        }

        if (addvendor(VENDOR_NAME, value) < 0) {
                (*errcnt)++;
        }

        return 0;

}

enum {
        KW_INCLUDE,
        KW_ATTRIBUTE,
	KW_ALIAS,
        KW_VALUE,
        KW_VENDOR,
	KW_PROPERTY
};

static struct keyword dict_kw[] = {
        { "$INCLUDE", KW_INCLUDE },
        { "ATTRIBUTE", KW_ATTRIBUTE },
	{ "ALIAS", KW_ALIAS },
        { "VALUE", KW_VALUE },
        { "VENDOR", KW_VENDOR },
	{ "PROPERTY", KW_PROPERTY },
        { NULL, 0 }
};

static int
parse_dict_entry(void *closure, int fc, char **fv, grad_locus_t *loc)
{
	int *errcnt = closure;
        switch (grad_xlat_keyword(dict_kw, KEYWORD, -1)) {
        case KW_INCLUDE:
                _dict_include(errcnt, fc, fv, loc);
                break;
        case KW_ATTRIBUTE:
                _dict_attribute(errcnt, fc, fv, loc);
                break;
	case KW_ALIAS:
		_dict_alias(errcnt, fc, fv, loc);
		break;
        case KW_VALUE:
                _dict_value(errcnt, fc, fv, loc);
                break;
        case KW_VENDOR:
                _dict_vendor(errcnt, fc, fv, loc);
                break;
	case KW_PROPERTY:
		_dict_property(errcnt, fc, fv, loc);
		break;
        default:
                grad_log_loc(L_ERR, loc, "%s", _("unknown keyword"));
                break;
        }
        return 0;
}

static int
parse_dict(char *name)
{
        char *path;
        int   rc;
        int   errcnt = 0;

	if (name[0] == '/')
		path = grad_estrdup(name);
	else
		path = grad_mkfilename(radius_dir, name);
        rc = grad_read_raddb_file(path, 1, NULL, parse_dict_entry, &errcnt);
        if (errcnt)
                grad_log(L_NOTICE,
		         ngettext("%s: %d error", "%s: %d errors",
			  	  errcnt), path, errcnt);
        grad_free(path);
        return rc;
}

int
grad_dict_init()
{
	if (!attr_parser_tab) {
		/* Register ascend filters */
		dict_register_parser(242, grad_ascend_parse_filter);
		dict_register_parser(243, grad_ascend_parse_filter);
	}
        dict_free();
        return parse_dict(RADIUS_DICTIONARY);
}

/* **************************************************************************
 * Lookup functions
 */

/*
 * Return the full attribute structure based on the
 * attribute id number.
 */

struct attr_value {
        unsigned value;
        grad_dict_attr_t *da;
};

static int
attrval_cmp(void *data, grad_symbol_t *s)
{
	struct attr_value *av = data;
	DICT_SYMBOL *sym = (DICT_SYMBOL *) s;
	
	if (sym->type == dict_symbol_attribute
	    && sym->v.attr.value == av->value) {
                av->da = &sym->v.attr;
		return 1;
        }
        return 0;
}

grad_dict_attr_t *
grad_attr_number_to_dict(int attribute)
{
        struct attr_value av;
        if (attribute >= 0 && attribute < DICT_INDEX_SIZE)
                return dict_attr_index[attribute];
        av.value = attribute;
        av.da = NULL;
        grad_symtab_iterate(dict_attr_tab, attrval_cmp, &av);
        return av.da;
}

/*
 *  Return the full attribute structure based on the attribute name.
 */

grad_dict_attr_t *
grad_attr_name_to_dict(char *attrname)
{
        return dict_attr_lookup(attrname);
}

/*
 * Return the full value structure based on the value name.
 */
struct val_lookup {
        char *name;
        char *attrname;
        int number;
};

static int
valname_cmp(const void *item, const void *data)
{
	const grad_dict_value_t *v = item;
	const struct val_lookup *d = data;
        if (d->number == v->attr->value && strcmp(v->name, d->name) == 0) 
		return 0;
	return 1;
}

grad_dict_value_t *
grad_value_name_to_value(char *valname, int attr)
{
        struct val_lookup data;
        data.name = valname;
        data.number = attr;
	return grad_list_locate(dictionary_values, &data, valname_cmp);
}

/*
 * Return the full value structure based on the actual value and
 * the associated attribute name.
 */
static int
valnum_cmp(const void *item, const void *data)
{
	const grad_dict_value_t *v = item;
	const struct val_lookup *d = data;

        if (strcmp(d->attrname, v->attr->name) == 0 && d->number == v->value) 
		return 0;
	return 1;
}

grad_dict_value_t *
grad_value_lookup(grad_uint32_t value, char *attrname)
{
        struct val_lookup data;
        data.number = value;
        data.attrname = attrname;
	return grad_list_locate(dictionary_values, &data, valnum_cmp);
}

/*
 * Get the PEC (Private Enterprise Code) of the vendor
 * based on it's internal number.
 */
static int
code_cmp(const void *item, const void *data)
{
	const grad_dict_vendor_t *v = item;
	const int *code = data;

        return v->vendorcode != *code;
}

int 
grad_vendor_id_to_pec(int code)
{
        grad_dict_vendor_t *vp;

	vp = grad_list_locate(dictionary_vendors, &code, code_cmp);
        return vp ? vp->vendorpec : 0;
}

/*
 * Get the internal code of the vendor based on its PEC.
 */
static int
pec_cmp(const void *item, const void *data)
{
	const grad_dict_vendor_t *v = item;
	const int *pec = data;

        return v->vendorpec != *pec;
}

int 
grad_vendor_pec_to_id(int pec)
{
        grad_dict_vendor_t *vp;

	vp = grad_list_locate(dictionary_vendors, &pec, pec_cmp);
        return vp ? vp->vendorcode : 0;
}
        
char *
grad_vendor_pec_to_name(int pec)
{
        grad_dict_vendor_t *vp;

	vp = grad_list_locate(dictionary_vendors, &pec, pec_cmp);
        return vp ? vp->vendorname : NULL;
}
        

/*
 * Get the internal code of the vendor based on its name.
 */
static int
vendor_cmp(const void *item, const void *data)
{
	const grad_dict_vendor_t *v = item;
	const char *s = data;

        return strcmp(v->vendorname, s);
}

int 
grad_vendor_name_to_id(char *name)
{
        grad_dict_vendor_t *vp;

	vp = grad_list_locate(dictionary_vendors, name, vendor_cmp);
        return vp ? vp->vendorcode : 0;
}

struct dict_iterator {
	dict_iterator_fp fp;
	void *closure;
};

int
dict_iter_helper(void *data, grad_symbol_t *symbol)
{
	struct dict_iterator *p = data;
	DICT_SYMBOL *dsym = (DICT_SYMBOL *) symbol;
	grad_dict_attr_t *attr;

	return p->fp(p->closure, dsym->name, dict_symbol_ptr(dsym));
}
	
void
grad_dictionary_iterate(dict_iterator_fp fp, void *closure)
{
	static struct dict_iterator d;
	d.fp = fp;
	d.closure = closure;
	grad_symtab_iterate(dict_attr_tab, dict_iter_helper, &d);
}

struct dict_value_iterator {
	dict_value_iterator_fp fp;
	void *closure;
};

static int
dict_value_iter_helper(void *item, void *data)
{
	struct dict_value_iterator *p = data;
	return p->fp(p->closure, item);
}

void
grad_dictionary_value_iterate(dict_value_iterator_fp fp, void *closure)
{
	static struct dict_value_iterator d;
	d.fp = fp;
	d.closure = closure;
	grad_list_iterate(dictionary_values, dict_value_iter_helper, &d);
}


