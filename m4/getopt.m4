## $Id$

## Check for getopt_long. This can't be done in AC_CHECK_FUNCS since
## the function can be present in different libraries (namely, libmysqlclient)
## but the necessary header files may be absent, thus AC_CHECK_FUNCS will
## mark function as existent, whereas the compilation will bail out.
AC_DEFUN(rad_FUNC_GETOPT_LONG,
[
 AC_CACHE_CHECK([for getopt_long], rad_cv_func_getopt_long,
  [AC_TRY_RUN([
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

struct option longopt[] = {
	"help",    no_argument,       0, 'h',
        (char*)0
};

main(argc, argv)
int argc; char **argv;
{
	getopt_long(argc, argv, "h", longopt, (int*)0);
	return 0;
}             ],
              rad_cv_func_getopt_long=yes,
              rad_cv_func_getopt_long=no,
              rad_cv_func_getopt_long=no)])

 if test $rad_cv_func_getopt_long = yes ; then
   AC_DEFINE(HAVE_GETOPT_LONG)
 fi
])


## Check whether getopt() supports GNU extensions: namely double
## column meaning optional argument
AC_DEFUN(rad_FUNC_GNU_GETOPT,
[
 AC_CACHE_CHECK([whether getopt supports GNU extensions],
                rad_cv_func_gnu_getopt,
  [AC_TRY_RUN([
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

int
run(argc, argv)
	int argc; char **argv;
{
	int c;
	int rc=0;
	while ((c = getopt(argc, argv, "a::b::c")) != -1) {
		switch (c) {
		case 'a':
		case 'b':
			rc = 10*rc + (optarg != (char*)0);
		case 'c':
			break;
		default:
			exit(1);
		}
	}
	return rc;
}

char *argv[] = {
	"arg0",
	"-a35",
	"-b",
	"-c",
	NULL
};

main()
{
	exit(run(4, argv) != 10);
}
              ],
              rad_cv_func_gnu_getopt=yes, 
              rad_cv_func_gnu_getopt=no,
              rad_cv_func_gnu_getopt=no)])
 if test $rad_cv_func_gnu_getopt = yes ; then
   AC_DEFINE(HAVE_GNU_GETOPT)
 fi
])

