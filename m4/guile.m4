dnl This file is part of GNU RADIUS.
dnl Copyright (C) 2001, Sergey Poznyakoff
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
dnl
AC_DEFUN(rad_CHECK_GUILE,
[
 if test "x$rad_cv_lib_guile" = x; then
   cached=""
   AC_PATH_PROG(GUILE_CONFIG, guile-config, no, $PATH)
   if test $GUILE_CONFIG = no; then
     rad_cv_lib_guile=no
   else
     GUILE_INCLUDES=`guile-config compile`
     GUILE_LIBS=`guile-config link`
   fi

   if test $GUILE_CONFIG != no; then
     AC_MSG_CHECKING(for guile version 1.4 or higher)
     GV=`($GUILE_CONFIG --version 2>&1; echo '')|sed -n 's/guile-config - Guile version \([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\).*/\1\2/p'`
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
   GUILE_INCLUDES=`guile-config compile`
   GUILE_LIBS=`guile-config link`
 fi
 AC_MSG_CHECKING(whether to build guile support)
 rad_RESULT_ACTIONS([rad_cv_lib_guile],[LIBGUILE],[$2],[$3])
 AC_MSG_RESULT(${cached}$rad_cv_lib_guile)
])
 
	

