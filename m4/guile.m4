AC_DEFUN(rad_CHECK_GUILE,
[
 if test "x$rad_cv_lib_guile" = x; then
   cached=""
   AC_PATH_PROG(GUILE_CONFIG, guile-config, no, $PATH)
   if test $GUILE_CONFIG != no; then
     GUILE_INCLUDES=`guile-config compile`
     GUILE_LIBS=`guile-config link`
   else
     rad_cv_lib_guile=no
   fi

   if test $GUILE_CONFIG != no; then
     AC_MSG_CHECKING(for guile version 1.4 or higher)
     GV=`$GUILE_CONFIG --version 2>&1|sed -n 's/guile-config - Guile version \([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\).*/\1\2/p'`
     case "x$GV" in
     x[[0-9]]*)
       if test $GV -lt 14; then
         AC_MSG_RESULT(Nope. Version number too low.)
         rad_cv_lib_guile=no
       else
         AC_MSG_RESULT(OK)
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
       fi ;;
     *) AC_MSG_RESULT(Nope. Unknown version number)
        rad_cv_lib_guile=no;;
     esac
   fi
 else
   cached=" (cached) "
 fi
 AC_MSG_CHECKING(whether to build guile support)
 rad_RESULT_ACTIONS([rad_cv_lib_guile],[LIBGUILE],[$2],[$3])
 AC_MSG_RESULT(${cached}$rad_cv_lib_guile)
])
 
	

