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
        
        if (SCM_IMP(NAME) && SCM_INUMP(NAME)) {
                attr = grad_attr_number_to_dict(SCM_INUM(NAME));
        } else if (SCM_NIMP(NAME) && SCM_STRINGP(NAME)) {
                attr = grad_attr_name_to_dict(SCM_STRING_CHARS(NAME));
        } else {
                SCM_ASSERT(0, NAME, SCM_ARG1, FUNC_NAME);
        }

        if (!attr)
                return SCM_BOOL_F;

        vendor = GRAD_VENDOR_CODE(attr->value);
        return scm_list_4(scm_makfrom0str(attr->name),
                         SCM_MAKINUM(vendor ?
                                     attr->value - (vendor << 16) :
                                     attr->value),
                         SCM_MAKINUM(attr->type),
                         vendor ?
                         SCM_MAKINUM(grad_vendor_id_to_pec(vendor)) :
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

        if (SCM_IMP(ATTR) && SCM_INUMP(ATTR)) {
                attr = grad_attr_number_to_dict(SCM_INUM(ATTR));
        } else if (SCM_NIMP(ATTR) && SCM_STRINGP(ATTR)) {
                attr = grad_attr_name_to_dict(SCM_STRING_CHARS(ATTR));
        }

        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(ATTR));
        }

        SCM_ASSERT((SCM_IMP(VALUE) && SCM_INUMP(VALUE)),
                   VALUE, SCM_ARG1, FUNC_NAME);
        val = grad_value_lookup(SCM_INUM(VALUE), attr->name);
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
        
        if (SCM_IMP(ATTR) && SCM_INUMP(ATTR)) {
                attr = grad_attr_number_to_dict(SCM_INUM(ATTR));
        } else if (SCM_NIMP(ATTR) && SCM_STRINGP(ATTR)) {
                attr = grad_attr_name_to_dict(SCM_STRING_CHARS(ATTR));
        }
        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               scm_list_1(ATTR));
        }
	SCM_ASSERT (SCM_NIMP(VALUE) && SCM_STRINGP(VALUE),
		    VALUE, SCM_ARG2, FUNC_NAME);
        
        /*FIXME:
          val = grad_value_name_to_value_strict(attr->value, SCM_STRING_CHARS(VALUE));
          */
        val = grad_value_name_to_value(SCM_STRING_CHARS(VALUE), attr->value);
        return val ? scm_long2num(val->value) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_pec_to_vendor, "rad-dict-pec->vendor", 1, 0, 0,
           (SCM PEC),
"Converts PEC to the vendor name")         
#define FUNC_NAME s_rad_dict_pec_to_vendor
{
        char *s;
        
        SCM_ASSERT(SCM_IMP(PEC) && SCM_INUMP(PEC), PEC, SCM_ARG1, FUNC_NAME);
        s = grad_vendor_pec_to_name(SCM_INUM(PEC));
        return s ? scm_makfrom0str(s) : SCM_BOOL_F;
}
#undef FUNC_NAME

void
rscm_dict_init()
{
#include <rscm_dict.x>
}
