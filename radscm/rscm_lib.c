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

SCM
radscm_avl_to_list(grad_avp_t *pair)
{
        SCM scm_first = SCM_EOL, scm_last;
        
        for (; pair; pair = pair->next) {
                SCM new = scm_cons(radscm_avp_to_cons(pair), SCM_EOL);
                if (scm_first == SCM_EOL) {
                        scm_last = scm_first = new;
                } else {
                        SCM_SETCDR(scm_last, new);
                        scm_last = new;
                }
        }
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
                scm_attr = scm_from_int(pair->attribute);
        switch (pair->type) {
        case GRAD_TYPE_STRING:
        case GRAD_TYPE_DATE:
                scm_value = scm_makfrom0str(pair->avp_strvalue);
                break;
        case GRAD_TYPE_INTEGER:
                scm_value = scm_from_long(pair->avp_lvalue);
                break;
        case GRAD_TYPE_IPADDR:
                scm_value = scm_from_ulong(pair->avp_lvalue);
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
        if (scm_is_integer(car)) {
                pair.attribute = scm_to_int(car);
                dict = grad_attr_number_to_dict(pair.attribute);
                if (!dict) 
                        return NULL;
                pair.name = dict->name;
        } else if (scm_is_string(car)) {
                /* FIXME: this may fail in future Guile versions */
                pair.name = scm_i_string_chars(car);
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
        case GRAD_TYPE_INTEGER:
                if (scm_is_integer(cdr)) {
                        pair.avp_lvalue = scm_to_long(cdr);
                } else if (SCM_BIGP(cdr)) {
                        pair.avp_lvalue = (grad_uint32_t) scm_i_big2dbl(cdr);
                } else if (scm_is_string(cdr)) {
                        const char *name = scm_i_string_chars(cdr);
			char *endp;
                        val = grad_value_name_to_value(name, pair.attribute);
                        if (val) {
                                pair.avp_lvalue = val->value;
                        } else {
                                pair.avp_lvalue = strtol(name, &endp, 0);
                                if (*endp)
                                        return NULL;
                        }
                } else
                        return NULL;
                break;
                
        case GRAD_TYPE_IPADDR:
                if (scm_is_integer(cdr)) {
                        pair.avp_lvalue = scm_to_long(cdr);
                } else if (SCM_BIGP(cdr)) {
                        pair.avp_lvalue = (grad_uint32_t) scm_i_big2dbl(cdr);
                } else if (scm_is_string(cdr)) {
                        pair.avp_lvalue =
				grad_ip_gethostaddr(scm_i_string_chars(cdr));
                } else
                        return NULL;
                break;
        case GRAD_TYPE_STRING:
        case GRAD_TYPE_DATE:
                if (!scm_is_string(cdr))
                        return NULL;
                pair.avp_strvalue = grad_estrdup(scm_i_string_chars(cdr));
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
	SCM *pscm;
	
        path_scm = RAD_SCM_SYMBOL_VALUE("%load-path");
        for (scm = path_scm; scm != SCM_EOL; scm = SCM_CDR(scm)) {
                SCM val = SCM_CAR(scm);
                if (scm_is_string(val))
                        if (strcmp(scm_i_string_chars(val), path) == 0)
                                return;
        }

	pscm = SCM_VARIABLE_LOC(scm_c_lookup("%load-path"));
	*pscm = scm_append(scm_list_3(path_scm,
				      scm_list_1(scm_makfrom0str(path)),
				      SCM_EOL));
}

void
grad_scm_init()
{
        rscm_syslog_init();
        rscm_utmp_init();
        rscm_avl_init();
        rscm_dict_init();
	rscm_hash_init();
#include <rscm_lib.x>
        rscm_add_load_path(DATADIR);
}
