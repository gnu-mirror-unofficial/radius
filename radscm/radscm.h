SCM scm_makenum (unsigned long val);
SCM radscm_avl_to_list(VALUE_PAIR *pair);
VALUE_PAIR *radscm_list_to_avl(SCM list);
SCM radscm_avp_to_cons(VALUE_PAIR *pair);
VALUE_PAIR *radscm_cons_to_avp(SCM scm);
void radscm_init();
