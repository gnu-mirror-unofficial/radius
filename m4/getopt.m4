## $Id$

## Check for getopt_long. This can't be done in AC_CHECK_FUNCS since
## the function can be present in different libraries (namely, libmysqlclient)
## but the necessary header files may be absent, thus AC_CHECK_FUNCS will
## mark function as existent, whereas the compilation will bail out.

## Just specifying AC_REPLACE_GNU_GETOPT in configure.in does not work
## since automake (at least up to version 1.4) does not provide this
## defun.

AC_DEFUN(rad_REPLACE_GNU_GETOPT,
[
 AC_CACHE_CHECK([for GNU getopt], rad_cv_have_gnu_getopt,
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
              rad_cv_have_gnu_getopt=yes,
              rad_cv_have_gnu_getopt=no,
              rad_cv_have_gnu_getopt=no)])

 if test x"$rad_cv_have_gnu_getopt" != xyes ; then
   LIBOBJS="$LIBOBJS getopt.o getopt1.o"
 else
   AC_DEFINE(HAVE_GNU_GETOPT)
 fi
])




