/*
 * Data types
 */
typedef enum {
        Undefined,
        Integer,
        String,
        Max_datatype
} Datatype;

typedef union {
        int       ival;
        char      *sval;
} Datum;

int interpret(char *fcall, RADIUS_REQ *req, Datatype *type, Datum *datum);

#ifdef RADIUS_SERVER_GUILE
SCM radscm_datum_to_scm(Datatype type, Datum datum);
int radscm_scm_to_ival(SCM cell, int *val);
SCM radscm_rewrite_execute(char *func_name, SCM ARGS);
#endif
