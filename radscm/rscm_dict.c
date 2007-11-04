/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation, Inc.

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

SCM_DEFINE(rad_dict_name_to_attr, "rad-dict-name->attr", 1, 0, 0,
           (SCM NAME),
"Returns a dictionary entry for the given attribute NAME or #f if\n"
"no such name was found in the dictionary.\n"
"The entry is a list of the form:\n"
"\n"
"       (NAME-STRING ATTR-NUMBER TYPE-NUMBER VENDOR)\n"
"\n"
"Where,\n"
"       NAME-STRING     is the attribute name,\n"
"       VALUE-NUMBER    is the attribute number,\n"
"       TYPE-NUMBER     is the attribute type\n"
"       VENDOR          is the vendor PEC, if the attribute is a\n"
"                       Vendor-Specific one, or #f otherwise.\n")
#define FUNC_NAME s_rad_dict_name_to_attr          
{
        grad_dict_attr_t *attr;
        int vendor;
        
        if (scm_is_integer(NAME)) {
                attr = grad_attr_number_to_dict(scm_to_int(NAME));
        } else if (scm_is_string(NAME)) {
                attr = grad_attr_name_to_dict(scm_i_string_chars(NAME));
        } else {
                SCM_ASSERT(0, NAME, SCM_ARG1, FUNC_NAME);
        }

        if (!attr)
                return SCM_BOOL_F;

        vendor = GRAD_VENDOR_CODE(attr->value);
        return scm_list_4(scm_makfrom0str(attr->name),
                          scm_from_int(vendor ?
                                       attr->value - (vendor << 16) :
                                       attr->value),
                         scm_from_int(attr->type),
                         vendor ?
                         scm_from_int(grad_vendor_id_to_pec(vendor)) :
                         SCM_BOOL_F);
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_value_to_name, "rad-dict-value->name", 2, 0, 0,
           (SCM ATTR, SCM VALUE),
"Returns a dictionary name of the given value of an integer-type\n"
"attribute\n")     
#define FUNC_NAME s_rad_dict_value_to_name
{
        grad_dict_attr_t *attr;
        grad_dict_value_t *val;

        if (scm_is_integer(ATTR)) {
                attr = grad_attr_number_to_dict(scm_to_int(ATTR));
        } else if (scm_is_string(ATTR)) {
                attr = grad_attr_name_to_dict(scm_i_string_chars(ATTR));
        }

        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(ATTR));
        }

        SCM_ASSERT(scm_is_integer(VALUE), VALUE, SCM_ARG1, FUNC_NAME);
        val = grad_value_lookup(scm_to_int(VALUE), attr->name);
	if (!val)
		scm_misc_error(FUNC_NAME,
                               "Value ~S not defined for attribute ~S",
                               scm_list_2(VALUE, ATTR));
        return scm_makfrom0str(val->name);
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_name_to_value, "rad-dict-name->value", 2, 0, 0,
           (SCM ATTR, SCM VALUE),
"Convert a symbolic attribute value name into its integer representation\n")
#define FUNC_NAME s_rad_dict_name_to_value      
{
        grad_dict_attr_t *attr;
        grad_dict_value_t *val;
        
        if (scm_is_integer(ATTR)) {
                attr = grad_attr_number_to_dict(scm_to_int(ATTR));
        } else if (scm_is_string(ATTR)) {
                attr = grad_attr_name_to_dict(scm_i_string_chars(ATTR));
        }
        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(ATTR));
        }
	SCM_ASSERT(scm_is_string(VALUE), VALUE, SCM_ARG2, FUNC_NAME);
        
        /*FIXME:
          val = grad_value_name_to_value_strict(attr->value, scm_i_string_chars(VALUE));
          */
        val = grad_value_name_to_value(scm_i_string_chars(VALUE), attr->value);
        return val ? scm_from_long(val->value) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_pec_to_vendor, "rad-dict-pec->vendor", 1, 0, 0,
           (SCM PEC),
"Converts PEC to the vendor name")         
#define FUNC_NAME s_rad_dict_pec_to_vendor
{
        char *s;
        
        SCM_ASSERT(scm_is_integer(PEC), PEC, SCM_ARG1, FUNC_NAME);
        s = grad_vendor_pec_to_name(scm_to_int(PEC));
        return s ? scm_makfrom0str(s) : SCM_BOOL_F;
}
#undef FUNC_NAME

void
rscm_dict_init()
{
#include <rscm_dict.x>
}
