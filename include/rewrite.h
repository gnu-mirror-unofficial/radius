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

