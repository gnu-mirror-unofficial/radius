/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
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
#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <ctype.h>

#include <radiusd.h>
#include <slist.h>

static DICT_ATTR	*dictionary_attributes;
static DICT_VALUE	*dictionary_values;
static DICT_VENDOR	*dictionary_vendors;
static int               vendorno;

int nfields(int  fc, int  minf, int  maxfm, char *file, int  lineno);

/* ************************************************************************ */

void
dict_free()
{
	free_slist((struct slist*)dictionary_attributes, NULL);
	free_slist((struct slist*)dictionary_values, NULL);
	free_slist((struct slist*)dictionary_vendors, NULL);

	dictionary_attributes = NULL;
	dictionary_values = NULL;
	dictionary_vendors = NULL;
	vendorno = 1;
}

int
nfields(fc, minf, maxf, file, lineno)
	int  fc;
	int  minf;
	int  maxf;
	char *file;
	int  lineno;
{
	if (fc < minf) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: too few fields"),
		       file, lineno);
		return -1;
	} else if (fc > maxf) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: too many fields"),
		       file, lineno);
		return -1;
	}
	return 0;
}

/*
 *	Add vendor to the list.
 */
int
addvendor(name, value)
	char *name;
	int value;
{
	DICT_VENDOR *vval;

	vval = Alloc_entry(DICT_VENDOR);
	
	strcpy(vval->vendorname, name);
	vval->vendorpec  = value;
	vval->vendorcode = vendorno++;

	/* Insert at front. */
	vval->next = dictionary_vendors;
	dictionary_vendors = vval;

	return 0;
}

/* **************************************************************************
 * Parser
 */
#define KEYWORD      fv[0]
#define ATTR_NAME    fv[1]
#define ATTR_VALUE   fv[2]
#define ATTR_TYPE    fv[3]
#define ATTR_VENDOR  fv[4]
#define HAS_VENDOR(c) (c==5)
#define VALUE_ATTR   fv[1]
#define VALUE_NAME   fv[2]
#define VALUE_NUM    fv[3]
#define VENDOR_NAME  fv[1]
#define VENDOR_VALUE fv[2]

static int _dict_include(int *, int, char **, char *, int);
static int _dict_attribute(int *, int, char **, char *, int);
static int _dict_value(int *, int, char **, char *, int);
static int _dict_vendor(int *, int, char **, char *, int);
static int parse_dict_entry(int *, int, char **, char *, int);
static int parse_dict(char *name);

static struct keyword type_kw[] = {
	"string", PW_TYPE_STRING,
	"integer", PW_TYPE_INTEGER,
	"ipaddr", PW_TYPE_IPADDR,
	"date", PW_TYPE_DATE
};

/*ARGSUSED*/
int
_dict_include(errcnt, fc, fv, file, lineno)
	int    *errcnt;
	int     fc;
	char    **fv;
	char    *file;
	int     lineno;
{
	if (nfields(fc, 2, 2, file, lineno)) 
		return 0;
	parse_dict(fv[1]);
	return 0;
}


int
_dict_attribute(errcnt, fc, fv, file, lineno)
	int    *errcnt;
	int     fc;
	char    **fv;
	char    *file;
	int     lineno;
{
	DICT_ATTR	*attr;
	int              type;
	int              vendor = 0;
	int              value;
	char            *p;
	
	if (nfields(fc, 4, 5, file, lineno))
		return 0;
	/*
	 * Validate all entries
	 */
	if (strlen(ATTR_NAME) > MAX_DICTNAME) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: name too long"),
		       file, lineno);
		(*errcnt)++;
		return 0;
	}
	
	value = strtol(ATTR_VALUE, &p, 0);
	if (*p) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: value not a number (near %s)"),
		       file, lineno, p);
		(*errcnt)++;
		return 0;
	}

	if ((type = xlat_keyword(type_kw, ATTR_TYPE, PW_TYPE_INVALID)) ==
	    PW_TYPE_INVALID) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: invalid type"),
		       file, lineno);
		(*errcnt)++;
		return 0;
	}

	if (HAS_VENDOR(fc)) {
		if ((vendor = vendor_name_to_id(ATTR_VENDOR)) == 0) {
			radlog(L_ERR|L_CONS,
			       _("%s:%d: unknown vendor"),
			       file, lineno);
			(*errcnt)++;
			return 0;
		}
	}

	attr = Alloc_entry(DICT_ATTR);
			
	strcpy(attr->name, ATTR_NAME);
	attr->value = value;
	attr->type = type;
	if (vendor)
		attr->value |= (vendor << 16);
	
	/*
	 *	Add to the front of the list, so that
	 *	values at the end of the file override
	 *	those in the begin.
	 */
	attr->next = dictionary_attributes;
	dictionary_attributes = attr;
	return 0;
}

int
_dict_value(errcnt, fc, fv, file, lineno)
	int    *errcnt;
	int     fc;
	char    **fv;
	char    *file;
	int     lineno;
{
	DICT_VALUE	*dval;
	char            *p;
	int             value;
	
	if (nfields(fc, 4, 4, file, lineno))
		return 0;

	if (strlen(VALUE_NAME) > MAX_DICTNAME) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: value name too long"),
		       file, lineno);
		return 0;
	}
	if (strlen(VALUE_ATTR) > MAX_DICTNAME) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: value attribute name too long"),
		       file, lineno);
		return 0;
	}
	
	value = strtol(VALUE_NUM, &p, 0);
	if (*p) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: value not a number (near %s)"),
		       file, lineno, p);
		(*errcnt)++;
		return 0;
	}

	/* Create a new VALUE entry for the list */
	dval = Alloc_entry(DICT_VALUE);
			
	strcpy(dval->name, VALUE_NAME);
	strcpy(dval->attrname, VALUE_ATTR);
	dval->value = value;

	/* Insert at front. */
	dval->next = dictionary_values;
	dictionary_values = dval;
	
	return 0;
}

int
_dict_vendor(errcnt, fc, fv, file, lineno)
	int    *errcnt;
	int     fc;
	char    **fv;
	char    *file;
	int     lineno;
{
	int             value;
	char            *p;

	if (nfields(fc, 3, 3, file, lineno))
		return 0;
	if (strlen(VENDOR_NAME) > MAX_DICTNAME) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: vendor name too long"),
		       file, lineno);
		return 0;
	}
	value = strtol(VENDOR_VALUE, &p, 0);
	if (*p) {
		radlog(L_ERR|L_CONS,
		       _("%s:%d: value not a number (near %s)"),
		       file, lineno, p);
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
	KW_VALUE,
	KW_VENDOR
};

static struct keyword dict_kw[] = {
	"$INCLUDE", KW_INCLUDE,
	"ATTRIBUTE", KW_ATTRIBUTE,
	"VALUE", KW_VALUE,
	"VENDOR", KW_VENDOR,
	NULL, 0
};

int
parse_dict_entry(errcnt, fc, fv, file, lineno)
	int    *errcnt;
	int     fc;
	char    **fv;
	char    *file;
	int     lineno;
{
	switch (xlat_keyword(dict_kw, KEYWORD, -1)) {
	case KW_INCLUDE:
		_dict_include(errcnt, fc, fv, file, lineno);
		break;
	case KW_ATTRIBUTE:
		_dict_attribute(errcnt, fc, fv, file, lineno);
		break;
	case KW_VALUE:
		_dict_value(errcnt, fc, fv, file, lineno);
		break;
	case KW_VENDOR:
		_dict_vendor(errcnt, fc, fv, file, lineno);
		break;
	default:
		radlog(L_ERR|L_CONS,
		       _("%s:%d: name too long"),
		       file, lineno);
		break;
	}
	return 0;
}

int
parse_dict(name)
	char *name;
{
	char *path;
	int   rc;
	int   errcnt = 0;
	
	path = mkfilename(radius_dir, name);
	rc = read_raddb_file(path, 1, 5, parse_dict_entry, &errcnt);
	if (errcnt)
		radlog(L_NOTICE, _("%s: %d errors"), path, errcnt);
	efree(path);
	return rc;
}

int
dict_init()
{
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
int
attrval_cmp(a,attr)
	DICT_ATTR *a;
	int       attr;
{
	return a->value - attr;
}

DICT_ATTR *
attr_number_to_dict(attribute)
	int	attribute;
{
	return (DICT_ATTR *)find_slist((struct slist*) dictionary_attributes,
				       attrval_cmp,
				       (void*)attribute);
}

/*
 *  Return the full attribute structure based on the attribute name.
 */
int
attrname_cmp(a,attr)
	DICT_ATTR *a;
	char      *attr;
{
	return strcmp(a->name, attr);
}

DICT_ATTR *
attr_name_to_dict(attrname)
	char	*attrname;
{
	return (DICT_ATTR *)find_slist((struct slist*) dictionary_attributes,
				       attrname_cmp,
				       attrname);
}

/*
 * Return the full value structure based on the value name.
 */
int
valname_cmp(v, s)
	DICT_VALUE *v;
	char       *s;
{
	return strcmp(v->name, s);
}

DICT_VALUE *
value_name_to_value(valname)
	char	*valname;
{
	return (DICT_VALUE *)find_slist((struct slist*) dictionary_values,
					valname_cmp,
					valname);
}

/*
 * Return the full value structure based on the actual value and
 * the associated attribute name.
 */
int
value_cmp(a, b)
	DICT_VALUE *a, *b;
{
	return !(strcmp(a->attrname, b->attrname) == 0 &&
		 a->value == b->value);
}

DICT_VALUE *
value_lookup(value, attrname)
	UINT4	value;
	char	*attrname;
{
	DICT_VALUE val;

	strcpy(val.attrname, attrname);
	val.value = value;
	return (DICT_VALUE *)find_slist((struct slist*) dictionary_values,
					value_cmp,
					&val);
}

/*
 * Get the PEC (Private Enterprise Code) of the vendor
 * based on it's internal number.
 */
int
code_cmp(v, code)
	DICT_VENDOR *v;
	int code;
{
	return v->vendorcode - code;
}

int 
vendor_id_to_pec(code)
	int code;
{
	DICT_VENDOR *vp;

	vp = (DICT_VENDOR*)find_slist((struct slist*) dictionary_vendors,
				      code_cmp,
				      (void*)code);
	return vp ? vp->vendorpec : 0;
}

/*
 * Get the internal code of the vendor based on its PEC.
 */
int
pec_cmp(v, pec)
	DICT_VENDOR *v;
	int pec;
{
	return v->vendorpec - pec;
}

int 
vendor_pec_to_id(pec)
	int pec;
{
	DICT_VENDOR *vp;

	vp = (DICT_VENDOR*)find_slist((struct slist*) dictionary_vendors,
				      pec_cmp,
				      (void*)pec);
	return vp ? vp->vendorcode : 0;
}
	
char *
vendor_pec_to_name(pec)
	int pec;
{
	DICT_VENDOR *vp;

	vp = (DICT_VENDOR*)find_slist((struct slist*) dictionary_vendors,
				      pec_cmp,
				      (void*)pec);
	return vp ? vp->vendorname : NULL;
}
	

/*
 * Get the internal code of the vendor based on its name.
 */
int
vendor_cmp(v, s)
	DICT_VENDOR *v;
	char        *s;
{
	return strcmp(v->vendorname, s);
}

int 
vendor_name_to_id(name)
	char *name;
{
	DICT_VENDOR *vp;

	vp = (DICT_VENDOR*)find_slist((struct slist*) dictionary_vendors,
				      vendor_cmp,
				      name);
	return vp ? vp->vendorcode : 0;
}
	
