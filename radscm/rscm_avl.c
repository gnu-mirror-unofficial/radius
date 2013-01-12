/* This file is part of GNU Radius.
   Copyright (C) 2000, 2001, 2002, 2003, 2004, 2007, 2010, 2013 Free Software
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
   along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <libguile.h>
#include <radius/radius.h>
#include <radius/radscm.h>

SCM_DEFINE_PUBLIC(rscm_avl_delete, "avl-delete", 2, 0, 0,
		  (SCM list, SCM attr),
"Deletes from @var{list} pairs with attributes matching @var{attr}. "
"The latter is either a symbolic name of the attribute as defined in "
"the dictionary, or its number.\n")
#define FUNC_NAME s_rscm_avl_delete
{
        grad_avp_t *pairlist;
        int attr_no;
        SCM retval;

        SCM_ASSERT(scm_is_pair(list), list, SCM_ARG1, FUNC_NAME);
        pairlist = radscm_list_to_avl(list);
        if (scm_is_string(attr)) {
		char *str = scm_to_locale_string(attr);
                grad_dict_attr_t *da = grad_attr_name_to_dict(str);
		free(str);
                if (!da)
                        scm_misc_error(FUNC_NAME,
                                       "Unknown attribute: ~S",
                                       scm_list_1(attr));
                attr_no = da->value;
        } else {
                SCM_ASSERT(scm_is_integer(attr), attr, SCM_ARG2, FUNC_NAME);
                attr_no = scm_to_int(attr);
        }
        grad_avl_delete(&pairlist, attr_no);
        retval = radscm_avl_to_list(pairlist);
        grad_avl_free(pairlist);
        return retval;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rscm_avl_merge, "avl-merge", 2, 0, 0,
		  (SCM dstlist, SCM srclist),
"Merge @var{srclist} into @var{dstlist}.")
#define FUNC_NAME s_rscm_avl_merge
{
        grad_avp_t *dst, *src;
        SCM retval;
        
        SCM_ASSERT(scm_is_null(dstlist) || scm_is_pair(dstlist),
                   dstlist, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT(scm_is_null(srclist) || scm_is_pair(srclist),
                   srclist, SCM_ARG2, FUNC_NAME);
        dst = radscm_list_to_avl(dstlist);
        src = radscm_list_to_avl(srclist);
        grad_avl_merge(&dst, &src);
        retval = radscm_avl_to_list(dst);
        grad_avl_free(dst);
        grad_avl_free(src);
        return retval;
}
#undef FUNC_NAME

SCM_DEFINE_PUBLIC(rscm_avl_match_p, "avl-match?", 2, 0, 0,
		  (SCM target, SCM list),
"Return @samp{#t} if all pairs from @var{list} are also present in @var{target}")
#define FUNC_NAME s_rscm_avl_match_p
{
        grad_avp_t *target_pairs, *pair;
        grad_avp_t *list_pairs, *check_pair;
        int rc;

        SCM_ASSERT(scm_is_null(target) || scm_is_pair(target),
                   target, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT(scm_is_null(list) || scm_is_pair(list),
                   list, SCM_ARG2, FUNC_NAME);
        if (scm_is_null(target))
                target_pairs = NULL;
        else
                target_pairs =  radscm_list_to_avl(target);
        if (scm_is_null(list))
                list_pairs = NULL;
        else
                list_pairs =  radscm_list_to_avl(list);
        rc = 0;
        for (check_pair = list_pairs; !rc && check_pair;
             check_pair = check_pair->next) {
                for (pair = target_pairs;
                     pair && pair->attribute != check_pair->attribute;
                     pair = pair->next)
                        ;
                rc = !pair || grad_avp_cmp(check_pair, pair);
        }
        grad_avl_free(target_pairs);
        grad_avl_free(list_pairs);
        return rc == 0 ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


void
rscm_avl_init()
{
#include <rscm_avl.x>
}
