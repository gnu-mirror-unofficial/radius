dnl Arguments:
dnl   $1     --    Library to look for
dnl   $2     --    Function to check in the library
dnl   $3     --    Any additional libraries that might be needed
dnl   $4     --    Action to be taken when test succeeds
dnl   $5     --    Action to be taken when test fails
dnl   $6     --    Directories where the library may reside
AC_DEFUN(rad_CHECK_LIB,
[
  save_LIBS=$LIBS
  AC_CACHE_CHECK([for -l$1], rad_cv_lib_$1,
  [
   for path in $6
   do
      LIBS="$save_LIBS -L$path"
      AC_CHECK_LIB($1, $2,
                   [rad_cv_lib_$1="$3 -L$path -l$1"
                    break],
                   [rad_cv_lib_$1=no],$3)
   done
  ])
  rad_RESULT_ACTIONS([rad_cv_lib_$1],[LIB$1],[$4],[$5])
  LIBS=$save_LIBS
])


