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

SCM 
rad_scm_cell(SCM car, SCM cdr)
{
	SCM c;
	
	SCM_NEWCELL(c);
	SCM_SETCAR(c, car);
	SCM_SETCDR(c, cdr);
	return c;
}

#ifndef HAVE_SCM_LONG2NUM
SCM 
scm_long2num(long val)
{
  if (SCM_FIXABLE ((long) val))
    return SCM_MAKINUM (val);

#ifdef SCM_BIGDIG
  return scm_long2big (val);
#else /* SCM_BIGDIG */
  return scm_make_real ((double) val);
#endif /* SCM_BIGDIG */
}
#endif

SCM
radscm_avl_to_list(grad_avp_t *pair)
{
        SCM scm_first = SCM_EOL, scm_last;
        
        for (; pair; pair = pair->next) {
                SCM new = rad_scm_cell(radscm_avp_to_cons(pair), SCM_EOL);
                if (scm_first == SCM_EOL) {
                        scm_last = scm_first = new;
                } else {
                        SCM_SETCDR(scm_last, new);
                        scm_last = new;
                }
        }
        if (scm_first != SCM_EOL)
                SCM_SETCDR(scm_last, SCM_EOL);
        return scm_first;
}

grad_avp_t *
radscm_list_to_avl(SCM list)
{
        grad_avp_t *first, *last, *p;

        if (list == SCM_EOL)
                return NULL;
        first = last = NULL;
        do {
                p = radscm_cons_to_avp(SCM_CAR(list));
                if (p) {
                        p->next = NULL;
                        if (!last)
                                first = p;
                        else
                                last->next = p;
                        last = p;
                }
                list = SCM_CDR(list);
        } while (list != SCM_EOL);
        return first;
}


SCM
radscm_avp_to_cons(grad_avp_t *pair)
{
        SCM scm_attr, scm_value;
        grad_dict_attr_t *dict;
        
        if (dict = grad_attr_number_to_dict(pair->attribute)) 
                scm_attr = scm_makfrom0str(dict->name);
        else
                scm_attr = SCM_MAKINUM(pair->attribute);
        switch (pair->type) {
        case TYPE_STRING:
        case TYPE_DATE:
                scm_value = scm_makfrom0str(pair->avp_strvalue);
                break;
        case TYPE_INTEGER:
                scm_value = scm_long2num(pair->avp_lvalue);
                break;
        case TYPE_IPADDR:
                scm_value = scm_ulong2num(pair->avp_lvalue);
                break;
        default:
                abort();
        }

        return scm_cons(scm_attr, scm_value);
}

/*
 * (define scm (cons NAME VALUE))
 */

grad_avp_t *
radscm_cons_to_avp(SCM scm)
{
        SCM car, cdr;
        grad_dict_attr_t *dict;
        grad_dict_value_t *val;
        grad_avp_t pair, *p;
        
        if (!(SCM_NIMP(scm) && SCM_CONSP(scm)))
                return NULL;

        car = SCM_CAR(scm);
        cdr = SCM_CDR(scm);
        memset(&pair, 0, sizeof(pair));
        if (SCM_IMP(car) && SCM_INUMP(car)) {
                pair.attribute = SCM_INUM(car);
                dict = grad_attr_number_to_dict(pair.attribute);
                if (!dict) 
                        return NULL;
                pair.name = dict->name;
        } else if (SCM_NIMP(car) && SCM_STRINGP(car)) {
                pair.name = SCM_STRING_CHARS(car);
                dict = grad_attr_name_to_dict(pair.name);
                if (!dict) 
                        return NULL;
                pair.attribute = dict->value;
        } else
                return NULL;
        
        pair.type = dict->type;
        pair.operator = grad_operator_equal;
        pair.type = dict->type;
        pair.prop = dict->prop;

        switch (pair.type) {
        case TYPE_INTEGER:
                if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
                        pair.avp_lvalue = SCM_INUM(cdr);
                } else if (SCM_BIGP(cdr)) {
                        pair.avp_lvalue = (grad_uint32_t) scm_i_big2dbl(cdr);
                } else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
                        char *name = SCM_STRING_CHARS(cdr);
                        val = grad_value_name_to_value(name, pair.attribute);
                        if (val) {
                                pair.avp_lvalue = val->value;
                        } else {
                                pair.avp_lvalue = strtol(name, &name, 0);
                                if (*name)
                                        return NULL;
                        }
                } else
                        return NULL;
                break;
                
        case TYPE_IPADDR:
                if (SCM_IMP(cdr) && SCM_INUMP(cdr)) {
                        pair.avp_lvalue = SCM_INUM(cdr);
                } else if (SCM_BIGP(cdr)) {
                        pair.avp_lvalue = (grad_uint32_t) scm_i_big2dbl(cdr);
                } else if (SCM_NIMP(cdr) && SCM_STRINGP(cdr)) {
                        pair.avp_lvalue =
				grad_ip_gethostaddr(SCM_STRING_CHARS(cdr));
                } else
                        return NULL;
                break;
        case TYPE_STRING:
        case TYPE_DATE:
                if (!(SCM_NIMP(cdr) && SCM_STRINGP(cdr)))
                        return NULL;
                pair.avp_strvalue = grad_estrdup(SCM_STRING_CHARS(cdr));
                pair.avp_strlength = strlen(pair.avp_strvalue);
                break;
        default:
                abort();
        }

        p = grad_emalloc(sizeof(grad_avp_t));
        *p = pair;
        
        return p;
}

void
rscm_add_load_path(char *path)
{
        SCM scm, path_scm;
        path_scm = RAD_SCM_SYMBOL_VALUE("%load-path");
        for (scm = path_scm; scm != SCM_EOL; scm = SCM_CDR(scm)) {
                SCM val = SCM_CAR(scm);
                if (SCM_NIMP(val) && SCM_STRINGP(val))
                        if (strcmp(SCM_STRING_CHARS(val), path) == 0)
                                return;
        }
#if GUILE_VERSION == 14
        scm_c_define ("%load-path",
                       scm_append(scm_list_3(path_scm,
					     scm_list_1(scm_makfrom0str(path)),
					     SCM_EOL)));
#else
	{
		SCM *scm = SCM_VARIABLE_LOC(scm_c_lookup("%load-path"));
		*scm = scm_append(scm_list_3(path_scm,
					    scm_list_1(scm_makfrom0str(path)),
					    SCM_EOL));
	}
#endif
}

void
grad_scm_init()
{
        rscm_syslog_init();
        rscm_utmp_init();
        rscm_avl_init();
        rscm_dict_init();
#include <rscm_lib.x>
        rscm_add_load_path(DATADIR);
}
