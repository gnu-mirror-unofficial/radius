/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001 Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius.h>

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
        DICT_ATTR *attr;
        int vendor;
        
        if (SCM_IMP(NAME) && SCM_INUMP(NAME)) {
                attr = attr_number_to_dict(SCM_INUM(NAME));
        } else if (SCM_NIMP(NAME) && SCM_STRINGP(NAME)) {
                attr = attr_name_to_dict(SCM_CHARS(NAME));
        } else {
                SCM_ASSERT(0, NAME, SCM_ARG1, FUNC_NAME);
        }

        if (!attr)
                return SCM_BOOL_F;

        vendor = VENDOR(attr->value);
        return SCM_LIST4(scm_makfrom0str(attr->name),
                         SCM_MAKINUM(vendor ?
                                     attr->value - (vendor << 16) :
                                     attr->value),
                         SCM_MAKINUM(attr->type),
                         vendor ?
                         SCM_MAKINUM(vendor_id_to_pec(vendor)) :
                         SCM_BOOL_F);
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_value_to_name, "rad-dict-value->name", 2, 0, 0,
           (SCM ATTR, SCM VALUE),
"Returns a dictionary name of the given value of an integer-type\n"
"attribute\n")     
#define FUNC_NAME s_rad_dict_value_to_name
{
        DICT_ATTR *attr;
        DICT_VALUE *val;

        if (SCM_IMP(ATTR) && SCM_INUMP(ATTR)) {
                attr = attr_number_to_dict(SCM_INUM(ATTR));
        } else if (SCM_NIMP(ATTR) && SCM_STRINGP(ATTR)) {
                attr = attr_name_to_dict(SCM_CHARS(ATTR));
        }

        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               SCM_LIST1(ATTR));
                return SCM_BOOL_F;
        }

        SCM_ASSERT((SCM_IMP(VALUE) && SCM_INUMP(VALUE)),
                   VALUE, SCM_ARG1, FUNC_NAME);
        val = value_lookup(SCM_INUM(VALUE), attr->name);
        return val ? scm_makfrom0str(val->name) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_name_to_value, "rad-dict-name->value", 2, 0, 0,
           (SCM ATTR, SCM VALUE),
"Convert a symbolic attribute value name into its integer representation\n")
#define FUNC_NAME s_rad_dict_name_to_value      
{
        DICT_ATTR *attr;
        DICT_VALUE *val;
        
        if (SCM_IMP(ATTR) && SCM_INUMP(ATTR)) {
                attr = attr_number_to_dict(SCM_INUM(ATTR));
        } else if (SCM_NIMP(ATTR) && SCM_STRINGP(ATTR)) {
                attr = attr_name_to_dict(SCM_CHARS(ATTR));
        }
        if (!attr) {
                scm_misc_error(FUNC_NAME,
                               "Unknown attribute: ~S",
                               SCM_LIST1(ATTR));
        }
        SCM_ASSERT((SCM_NIMP(VALUE) && SCM_STRINGP(VALUE)),
                   VALUE, SCM_ARG1, FUNC_NAME);
        
        /*FIXME:
          val = value_name_to_value_strict(attr->value, SCM_CHARS(VALUE));
          */
        val = value_name_to_value(SCM_CHARS(VALUE), attr->value);
        return val ? scm_makenum(val->value) : SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE(rad_dict_pec_to_vendor, "rad-dict-pec->vendor", 1, 0, 0,
           (SCM PEC),
"Converts PEC to the vendor name")         
#define FUNC_NAME s_rad_dict_pec_to_vendor
{
        char *s;
        
        SCM_ASSERT(SCM_IMP(PEC) && SCM_INUMP(PEC), PEC, SCM_ARG1, FUNC_NAME);
        s = vendor_pec_to_name(SCM_INUM(PEC));
        return s ? scm_makfrom0str(s) : SCM_BOOL_F;
}
#undef FUNC_NAME

void
rscm_dict_init()
{
#ifndef SCM_MAGIC_SNARFER
# include <rscm_dict.x>
#endif
}
