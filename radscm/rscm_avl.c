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

SCM_DEFINE(rscm_avl_delete, "avl-delete", 2, 0, 0,
           (SCM LIST, SCM ATTR),
	   "Delete the pairs with the matching attribute")
#define FUNC_NAME s_rscm_avl_delete
{
        grad_avp_t *pairlist;
        int attr;
        SCM RETVAL;

        SCM_ASSERT(scm_is_pair(LIST), LIST, SCM_ARG1, FUNC_NAME);
        pairlist = radscm_list_to_avl(LIST);
        if (scm_is_string(ATTR)) {
		char *str = scm_to_locale_string(ATTR);
                grad_dict_attr_t *da = grad_attr_name_to_dict(str);
		free(str);
                if (!da)
                        scm_misc_error(FUNC_NAME,
                                       "Unknown attribute: ~S",
                                       scm_list_1(ATTR));
                attr = da->value;
        } else {
                SCM_ASSERT(scm_is_integer(ATTR), ATTR, SCM_ARG2, FUNC_NAME);
                attr = scm_to_int(ATTR);
        }
        grad_avl_delete(&pairlist, attr);
        RETVAL = radscm_avl_to_list(pairlist);
        grad_avl_free(pairlist);
        return RETVAL;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_avl_merge, "avl-merge", 2, 0, 0,
           (SCM DST, SCM SRC),
"Merge SRC into DST.")     
#define FUNC_NAME s_rscm_avl_merge
{
        grad_avp_t *dst, *src;
        SCM RETVAL;
        
        SCM_ASSERT(scm_is_null(DST) || scm_is_pair(DST),
                   DST, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT(scm_is_null(SRC) || scm_is_pair(SRC),
                   SRC, SCM_ARG2, FUNC_NAME);
        dst = radscm_list_to_avl(DST);
        src = radscm_list_to_avl(SRC);
        grad_avl_merge(&dst, &src);
        RETVAL = radscm_avl_to_list(dst);
        grad_avl_free(dst);
        grad_avl_free(src);
        return RETVAL;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_avl_match_p, "avl-match?", 2, 0, 0,
           (SCM TARGET, SCM LIST),
"Return #t if all pairs from LIST are present in TARGET")          
#define FUNC_NAME s_rscm_avl_match_p
{
        grad_avp_t *target, *pair;
        grad_avp_t *list, *check_pair;
        int rc;

        SCM_ASSERT(scm_is_null(TARGET) || scm_is_pair(TARGET),
                   TARGET, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT(scm_is_null(LIST) || scm_is_pair(LIST),
                   LIST, SCM_ARG2, FUNC_NAME);
        if (scm_is_null(TARGET))
                target = NULL;
        else
                target =  radscm_list_to_avl(TARGET);
        if (scm_is_null(LIST))
                list = NULL;
        else
                list =  radscm_list_to_avl(LIST);
        rc = 0;
        for (check_pair = list; !rc && check_pair;
             check_pair = check_pair->next) {
                for (pair = target;
                     pair && pair->attribute != list->attribute;
                     pair = pair->next)
                        ;
                rc = !pair || grad_avp_cmp(check_pair, pair);
        }
        grad_avl_free(target);
        grad_avl_free(list);
        return rc == 0 ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


void
rscm_avl_init()
{
#include <rscm_avl.x>
}
