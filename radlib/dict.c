/*
 *
 *	RADIUS
 *	Remote Authentication Dial In User Service
 *
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.   
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 */

#ifndef lint
static char rcsid[] = 
"$Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<pwd.h>
#include	<ctype.h>

#include	<radiusd.h>

static DICT_ATTR	*dictionary_attributes;
static DICT_VALUE	*dictionary_values;
static DICT_VENDOR	*dictionary_vendors;

static int		vendorno = 1;

#ifdef NOCASE
#define DICT_STRCMP strcasecmp
#else
#define DICT_STRCMP strcmp
#endif

static void dict_free(void);
static int addvendor(char *name, int value);

/*
 *	Free the dictionary_attributes and dictionary_values lists.
 */
void 
dict_free()
{
	DICT_ATTR	*dattr, *anext;
	DICT_VALUE	*dval, *vnext;
	DICT_VENDOR	*dvend, *enext;

	for (dattr = dictionary_attributes; dattr; dattr = anext) {
		anext = dattr->next;
		free_entry(dattr);
	}
	for (dval = dictionary_values; dval; dval = vnext) {
		vnext = dval->next;
		free_entry(dval);
	}
	for (dvend = dictionary_vendors; dvend; dvend = enext) {
		enext = dvend->next;
		free_entry(dvend);
	}
	dictionary_attributes = NULL;
	dictionary_values = NULL;
	dictionary_vendors = NULL;
	vendorno = 1;
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

/*
 * Initialize the dictionary.
 * Read all ATTRIBUTES into the dictionary_attributes list.
 * Read all VALUES into the dictionary_values list.
 *
 * Return number of errors encountered or -1 in case of memory shortage.
 */
int
dict_init(fn)
	char *fn;
{
	char    *path;
	FILE	*dictfd;
	char	dummystr[64];
	char	namestr[64];
	char	valstr[64];
	char	attrstr[64];
	char	typestr[64];
	char	vendorstr[64];
	int	line_no;
	int     errcnt;
	DICT_ATTR	*attr;
	DICT_VALUE	*dval;
	DICT_VENDOR	*v;
	char	buffer[256];
	int	value;
	int	type;
	int	vendor;
	int	is_attrib;
#ifdef ATTRIB_NMC
	int	vendor_usr_seen = 0;
	int	is_nmc = 0;
#endif

	if (fn == NULL)
		dict_free();

	if (fn) {
		if (fn[0] == '/')
			path = estrdup(fn);
		else
			path = mkfilename(radius_dir, fn);
	} else
		path = mkfilename(radius_dir, RADIUS_DICTIONARY);

	if ((dictfd = fopen(path, "r")) == (FILE *)NULL) {
		radlog(L_CONS|L_ERR, _("dict_init: couldn't open dictionary: %s"),
		       path);
		efree(path);
		return(-1);
	}

	line_no = 0;
	errcnt = 0;
	while (fgets(buffer, sizeof(buffer), dictfd) != (char *)NULL) {
		line_no++;
		
		/* Skip empty space */
		if (*buffer == '#' || *buffer == '\0' || *buffer == '\n') {
			continue;
		}

		if (strncasecmp(buffer, "$INCLUDE", 8) == 0) {

			/* Read the $INCLUDE line */
			if (sscanf(buffer, "%s%s", dummystr, valstr) != 2) {
				radlog(L_ERR, _("%s:%d: $INCLUDE syntax error"),
				       path, line_no);
				errcnt++;
				continue;
			}
			errcnt += dict_init(valstr);
			continue;
		}

		is_attrib = 0;
		if (strncmp(buffer, "ATTRIBUTE", 9) == 0)
			is_attrib = 1;
#ifdef ATTRIB_NMC
		is_nmc = 0;
		if (strncmp(buffer, "ATTRIB_NMC", 10) == 0)
			is_attrib = is_nmc = 1;
#endif
		if (is_attrib) {
			/* Read the ATTRIBUTE line */
			vendor = 0;
			vendorstr[0] = 0;
			if (sscanf(buffer, "%s%s%s%s%s", dummystr, namestr,
					valstr, typestr, vendorstr) < 4) {
				radlog(L_ERR,
				       _("%s:%d: syntax error"), path, line_no);
				errcnt++;
				continue;
			}

#ifdef ATTRIB_NMC
			/*
			 *	Convert ATTRIB_NMC into our format.
			 *	We might need to add USR to the list of
			 *	vendors first.
			 */
			if (is_nmc && vendorstr[0] == 0) {
				if (!vendor_usr_seen) {
					if (addvendor("USR", VENDORPEC_USR) < 0) {
						errcnt = -1;
						break;
					}
					vendor_usr_seen = 1;
				}
				strcpy(vendorstr, "USR");
			}
#endif

			/*
			 * Validate all entries
			 */
			if (strlen(namestr) > 31) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: name too long"),
				       path, line_no);
				errcnt++;
				continue;
			}

			if (!isdigit(*valstr)) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: value too long"),
				       path, line_no);
				errcnt++;
				continue;
			}
			if (valstr[0] != '0')
				value = atoi(valstr);
			else
				sscanf(valstr, "%i", &value);

			if (strcmp(typestr, "string") == 0) 
				type = PW_TYPE_STRING;
			else if (strcmp(typestr, "integer") == 0) 
				type = PW_TYPE_INTEGER;
			else if (strcmp(typestr, "ipaddr") == 0) 
				type = PW_TYPE_IPADDR;
			else if (strcmp(typestr, "date") == 0) 
				type = PW_TYPE_DATE;
			else {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: invalid type"),
				       path, line_no);
				errcnt++;
				continue;
			}

			for (v = dictionary_vendors; v; v = v->next) {
				if (strcmp(vendorstr, v->vendorname) == 0)
					vendor = v->vendorcode;
			}
			if (vendorstr[0] && !vendor) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: unknown vendor"),
				       path, line_no);
				errcnt++;
				continue;
			}

			/* Create a new attribute for the list */
			attr = Alloc_entry(DICT_ATTR);
			
			strcpy(attr->name, namestr);
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

		} else if (strncmp(buffer, "VALUE", 5) == 0) {

			/* Read the VALUE line */
			if (sscanf(buffer, "%s%s%s%s", dummystr, attrstr,
				   namestr, valstr) != 4) {
				radlog(L_ERR|L_CONS,
				       "%s:%d: syntax error",
				       path, line_no);
				errcnt++;
				continue;
			}

			/*
			 * Validate all entries
			 */
			if (strlen(attrstr) > 31) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: attribute too long"),
				       path, line_no);
				errcnt++;
				continue;
			}

			if (strlen(namestr) > 31) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: name too long"),
				       path, line_no);
				errcnt++;
				continue;
			}

			if (!isdigit(*valstr)) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: invalid value"),
				       path, line_no);
				errcnt++;
				continue;
			}
			value = atoi(valstr);

			/* Create a new VALUE entry for the list */
			dval = Alloc_entry(DICT_VALUE);
			
			strcpy(dval->attrname, attrstr);
			strcpy(dval->name, namestr);
			dval->value = value;

			/* Insert at front. */
			dval->next = dictionary_values;
			dictionary_values = dval;
		} else if (strncmp(buffer, "VENDOR", 6) == 0) {

			/* Read the VENDOR line */
			if (sscanf(buffer, "%s%s%s", dummystr, attrstr,
						valstr) != 3) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: syntax error"),
				       path, line_no);
				errcnt++;
				continue;
			}

			/*
			 * Validate all entries
			 */
			if (strlen(attrstr) > 31) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: attribute too long"),
				       path, line_no);
				errcnt++;
				continue;
			}

			if (!isdigit(*valstr)) {
				radlog(L_ERR|L_CONS,
				       _("%s:%d: invalid value"),
				       path, line_no);
				errcnt++;
				continue;
			}
			value = atoi(valstr);

			/* Create a new VENDOR entry for the list */
			if (addvendor(attrstr, value) < 0) {
				errcnt = -1;
				break;
			}
#ifdef ATTRIB_NMC
			if (value == VENDORPEC_USR)
				vendor_usr_seen = 1;
#endif
		}
	}
	fclose(dictfd);
	efree(path);
	return errcnt;
}

/*************************************************************************
 *
 *	Function: dict_attrget
 *
 *	Purpose: Return the full attribute structure based on the
 *		 attribute id number.
 *
 *************************************************************************/

DICT_ATTR	*
dict_attrget(attribute)
	int	attribute;
{
	DICT_ATTR	*attr;

	attr = dictionary_attributes;
	while(attr != (DICT_ATTR *)NULL) {
		if (attr->value == attribute) {
			return(attr);
		}
		attr = attr->next;
	}
	return((DICT_ATTR *)NULL);
}

/*************************************************************************
 *
 *	Function: dict_attrfind
 *
 *	Purpose: Return the full attribute structure based on the
 *		 attribute name.
 *
 *************************************************************************/

DICT_ATTR	*
dict_attrfind(attrname)
	char	*attrname;
{
	DICT_ATTR	*attr;

	attr = dictionary_attributes;
	while(attr != (DICT_ATTR *)NULL) {
		if (DICT_STRCMP(attr->name, attrname) == 0) {
			return(attr);
		}
		attr = attr->next;
	}
	return((DICT_ATTR *)NULL);
}

/*************************************************************************
 *
 *	Function: dict_valfind
 *
 *	Purpose: Return the full value structure based on the
 *		 value name.
 *
 *************************************************************************/

DICT_VALUE	*
dict_valfind(valname)
	char	*valname;
{
	DICT_VALUE	*val;

	val = dictionary_values;
	while(val != (DICT_VALUE *)NULL) {
		if (DICT_STRCMP(val->name, valname) == 0) {
			return(val);
		}
		val = val->next;
	}
	return((DICT_VALUE *)NULL);
}

/*************************************************************************
 *
 *	Function: dict_valget
 *
 *	Purpose: Return the full value structure based on the
 *		 actual value and the associated attribute name.
 *
 *************************************************************************/

DICT_VALUE	*
dict_valget(value, attrname)
	UINT4	value;
	char	*attrname;
{
	DICT_VALUE	*val;

	val = dictionary_values;
	while(val != (DICT_VALUE *)NULL) {
		if (DICT_STRCMP(val->attrname, attrname) == 0 &&
						val->value == value) {
			return(val);
		}
		val = val->next;
	}
	return((DICT_VALUE *)NULL);
}

/*
 *	Get the PEC (Private Enterprise Code) of the vendor
 *	based on it's internal number.
 */
int 
dict_vendorpec(code)
	int code;
{
	DICT_VENDOR	*v;

	for (v = dictionary_vendors; v; v = v->next)
		if (v->vendorcode == code)
			break;

	return v ? v->vendorpec : 0;
}

/*
 *	Get the internal code of the vendor based on its PEC.
 */
int 
dict_vendorcode(pec)
	int pec;
{
	DICT_VENDOR	*v;

	for (v = dictionary_vendors; v; v = v->next)
		if (v->vendorpec == pec)
			break;

	return v ? v->vendorcode : 0;
}

