/* Declaration of program_invocation_name and program_invocation_short_name
   for those libc's that don't already have it.  These variable are needed
   by the argp_ functions. */

char *program_invocation_short_name = 0;
char *program_invocation_name = 0;
