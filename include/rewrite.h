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
