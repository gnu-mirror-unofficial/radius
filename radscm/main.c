#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif

#include <getopt1.h>
#include <libguile.h>
#include <radius.h>


static void radscm_shell(void *closure, int argc, char **argv);

/*ARGSUSED*/
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
        /*app_setup();*/
        initlog(argv[0]);
        
        scm_boot_guile(argc, argv, radscm_shell, 0);
        /*NOTREACHED*/
}


