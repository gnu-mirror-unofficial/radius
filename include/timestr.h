typedef struct timespan TIMESPAN;

struct timespan {
	TIMESPAN *next;
	int      start;
	int      stop;
};

void ts_free(TIMESPAN *sp);
int ts_parse(TIMESPAN **sp, char *str, char **endp);
int ts_match(TIMESPAN *timespan, time_t *time_now, unsigned *rest);
int ts_check(char *str, time_t *time, unsigned *rest, char **endp);

#include <mem.h>
#define ALLOC alloc_entry
#define FREE free_entry
