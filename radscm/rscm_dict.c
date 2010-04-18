/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2004, 2007, 2010 Free Software
   Foundation, Inc.

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

#include <libguile.h>
#include <radius/radius.h>
#include <radius/radscm.h>

SCM_DEFINE_PUBLIC(rad_dict_name_to_attr, "rad-dict-name->attr", 1, 0, 0,
		  (SCM name),
"Looks up attribute @var{name} in radius dictionary and returns its "
"entry, or @samp{#f} if no such name was found in the dictionary.\n"
"Returned entry is a list:\n"
"@lisp\n"
"(@var{name-string} @var{attr-number} @var{type-number} @var{vendor})\n"
"@end lisp\n"
"@noindent\n"		  
"where:\n"
"@table @var\n"		  
"@item name-string\n"
"Attribute name.\n"
"@item value-number\n"
"Attribute number.\n"
"@item type-number\n"
"Attribute type.\n"
"@item vendor\n"
"Vendor PEC, if the attribute is a Vendor-Specific one, or @samp{#f} "
"otherwise.\n"
"@end table\n")
#define FUNC_NAME s_rad_dict_name_to_attr          
{
        grad_dict_attr_t *attr;
        int vendor;
        
        if (scm_is_integer(name))
                attr = grad_attr_number_to_dict(scm_to_int(name));
        else if (scm_is_string(name)) {
		char *str = scm_to_locale_string(name);
                attr = grad_attr_name_to_dict(str);
		free(str);
        } else {
                SCM_ASSERT(0, name, SCM_ARG1, FUNC_NAME);
        }

        if (!attr)
                return SCM_BOOL_F;

        vendor = GRAD_VENDOR_CODE(attr->value);
        return scm_list_4(scm_from_locale_string(attr->name),
                          scm_from_int(vendor ?
                                       attr->value - (vendor << 16) :
                                       attr->value),
			  scm_from_int(attr->type),
			  vendor ?
			  scm_from_int(grad_vendor_id_to_pec(vendor)) :
			  SCM_BOOL_F);
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_dict_value_to_name, "rad-dict-value->name", 2, 0, 0,
		  (SCM attribute, SCM value),
"Returns dictionary name of the given value of an integer-type "
"attribute.\n")     
#define FUNC_NAME s_rad_dict_value_to_name
{
        grad_dict_attr_t *attr;
        grad_dict_value_t *val;

        if (scm_is_integer(attribute)) {
                attr = grad_attr_number_to_dict(scm_to_int(attribute));
        } else if (scm_is_string(attribute)) {
		char *str = scm_to_locale_string(attribute);
                attr = grad_attr_name_to_dict(str);
		free(str);
        }

        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(attribute));
        }

        SCM_ASSERT(scm_is_integer(value), value, SCM_ARG2, FUNC_NAME);
        val = grad_value_lookup(scm_to_int(value), attr->name);
	if (!val)
		scm_misc_error(FUNC_NAME,
                               "Value ~S not defined for attribute ~S",
                               scm_list_2(value, attribute));
        return scm_from_locale_string(val->name);
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_dict_name_to_value, "rad-dict-name->value", 2, 0, 0,
		  (SCM attribute, SCM value),
"Convert a symbolic attribute value name into its integer representation.\n")
#define FUNC_NAME s_rad_dict_name_to_value      
{
        grad_dict_attr_t *attr;
        grad_dict_value_t *val;
	char *str;
	
        if (scm_is_integer(attribute)) {
                attr = grad_attr_number_to_dict(scm_to_int(attribute));
        } else if (scm_is_string(attribute)) {
		str = scm_to_locale_string(attribute);
                attr = grad_attr_name_to_dict(str);
		free(str);
        }
        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(attribute));
        }
	SCM_ASSERT(scm_is_string(value), value, SCM_ARG2, FUNC_NAME);
        
        /*FIXME:
          val = grad_value_name_to_value_strict(attr->value, scm_i_string_chars(VALUE));
          */
	str = scm_to_locale_string(value);
        val = grad_value_name_to_value(str, attr->value);
	free(str);
        return val ? scm_from_long(val->value) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rad_dict_pec_to_vendor, "rad-dict-pec->vendor", 1, 0, 0,
		  (SCM pec),
"Converts @var{pec} to vendor name.")
#define FUNC_NAME s_rad_dict_pec_to_vendor
{
        char *s;
        
        SCM_ASSERT(scm_is_integer(pec), pec, SCM_ARG1, FUNC_NAME);
        s = grad_vendor_pec_to_name(scm_to_int(pec));
        return s ? scm_from_locale_string(s) : SCM_BOOL_F;
}
#undef FUNC_NAME

void
rscm_dict_init()
{
#include <rscm_dict.x>
}
