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
#include <radscm.h>

SCM_DEFINE(rscm_avl_delete, "avl-delete", 2, 0, 0,
           (SCM LIST, SCM ATTR),
	   "Delete the pairs with the matching attribute")
#define FUNC_NAME s_rscm_avl_delete
{
        VALUE_PAIR *pairlist;
        int attr;
        SCM RETVAL;
        SCM_ASSERT(SCM_NIMP(LIST) && SCM_CONSP(LIST),
                   LIST, SCM_ARG1, FUNC_NAME);
        pairlist = radscm_list_to_avl(LIST);
        if (SCM_NIMP(ATTR) && SCM_STRINGP(ATTR)) {
                DICT_ATTR *da = attr_name_to_dict(SCM_STRING_CHARS(ATTR));
                if (!da)
                        scm_misc_error(FUNC_NAME,
                                       "Unknown attribute: ~S",
                                       scm_list_1(ATTR));
                attr = da->value;
        } else {
                SCM_ASSERT(SCM_IMP(ATTR) && SCM_INUMP(ATTR),
                           ATTR, SCM_ARG2, FUNC_NAME);
                attr = SCM_INUM(ATTR);
        }
        avl_delete(&pairlist, attr);
        RETVAL = radscm_avl_to_list(pairlist);
        avl_free(pairlist);
        return RETVAL;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_avl_merge, "avl-merge", 2, 0, 0,
           (SCM DST, SCM SRC),
"Merge SRC into DST.")     
#define FUNC_NAME s_rscm_avl_merge
{
        VALUE_PAIR *dst, *src;
        SCM RETVAL;
        
        SCM_ASSERT(DST == SCM_EOL || (SCM_NIMP(DST) && SCM_CONSP(DST)),
                   DST, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT(SRC == SCM_EOL || SCM_NIMP(SRC) && SCM_CONSP(SRC),
                   SRC, SCM_ARG2, FUNC_NAME);
        dst =  radscm_list_to_avl(DST);
        src =  radscm_list_to_avl(SRC);
        avl_merge(&dst, &src);
        RETVAL = radscm_avl_to_list(dst);
        avl_free(dst);
        avl_free(src);
        return RETVAL;
}
#undef FUNC_NAME

SCM_DEFINE(rscm_avl_match_p, "avl-match?", 2, 0, 0,
           (SCM TARGET, SCM LIST),
"Return #t if all pairs from LIST are present in TARGET")          
#define FUNC_NAME s_rscm_avl_match_p
{
        VALUE_PAIR *target, *pair;
        VALUE_PAIR *list, *check_pair;
        int rc;

        SCM_ASSERT((SCM_IMP(TARGET) && TARGET == SCM_EOL)
                   || (SCM_NIMP(TARGET) && SCM_CONSP(TARGET)),
                   TARGET, SCM_ARG1, FUNC_NAME);
        SCM_ASSERT((SCM_IMP(LIST) && LIST == SCM_EOL)
                   || (SCM_NIMP(LIST) && SCM_CONSP(LIST)),
                   LIST, SCM_ARG2, FUNC_NAME);
        if (TARGET == SCM_EOL)
                target = NULL;
        else
                target =  radscm_list_to_avl(TARGET);
        if (LIST == SCM_EOL)
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
                if (!pair) {
                        rc = 1;
                        break;
                }
                        
                switch (pair->type) {
                case TYPE_STRING:
                        rc = strcmp(check_pair->strvalue, pair->strvalue);
                        break;

                case TYPE_INTEGER:
                case TYPE_IPADDR:
                        rc = check_pair->lvalue != pair->lvalue;
                        break;
                        
                default:
                        rc = 1;
                        break;
                }
        }
        avl_free(target);
        avl_free(list);
        return rc == 0 ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


void
rscm_avl_init()
{
#include <rscm_avl.x>
}
