
#if defined(WITH_INCLUDED_ARGP)
# include <../lib/argp.h>
#else
# include <argp.h>
#endif

extern struct argp rad_common_argp;
extern struct argp_child rad_common_argp_child[];
error_t grad_argp_parse(const struct argp *argp,
                       int *pargc,
                       char **pargv[],
                       unsigned flags,
                       int *arg_index,
                       void *input);
