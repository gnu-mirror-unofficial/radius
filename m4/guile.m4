AC_DEFUN(rad_CHECK_GUILE,
[
 AC_PATH_PROG(GUILE_CONFIG, guile-config, no, $PATH)
 AC_MSG_CHECKING(for usable guile libraries)
 if test $GUILE_CONFIG != no; then
   GUILE_INCLUDES=`guile-config compile`
   GUILE_LIBS=`guile-config link`
 fi
 if test "x$rad_cv_lib_guile" = x; then
   if test $GUILE_CONFIG != no; then
     save_LIBS=$LIBS
     save_CFLAGS=$CFLAGS
     LIBS="$LIBS $GUILE_LIBS"
     CFLAGS="$CFLAGS $GUILE_INCLUDES"
     AC_TRY_LINK([#include <libguile.h>],
                 void main(argc, argv) int argc; char **argv;
                  { ifelse([$1], , scm_shell(argc, argv);, [$1]) },
                 [rad_cv_lib_guile=yes],
                 [rad_cv_lib_guile=no])
     LIBS=$save_LIBS
     CFLAGS=$save_CFLAGS
     cached=""
   fi
 else
   cached=" (cached) "
 fi
 rad_RESULT_ACTIONS([rad_cv_lib_guile],[LIBGUILE],[$2],[$3])
 AC_MSG_RESULT(${cached}$rad_cv_lib_guile)
])
 
	

