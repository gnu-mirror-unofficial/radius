#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#if defined(HAVE_GETOPT_LONG)
# include <getopt.h>
#endif
#include <libguile.h>
#include <radiusd.h>


static void radscm_shell(void *closure, int argc, char **argv);
static void print_usage();
static void print_license();
static void print_version();
static void assign(char *);

void
radscm_shell(closure, argc, argv)
	void *closure;
	int  argc;
	char **argv;
{
	rad_scheme_init(argc, argv);
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	
	/*app_setup();*/
	initlog(argv[0]);
	
	scm_boot_guile(argc, argv, radscm_shell, 0);
	/*NOTREACHED*/
	return 0;
}


