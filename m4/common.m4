dnl rad_FLUSHLEFT -- remove all whitespace at the beginning of lines
dnl This is useful for c-code which may include cpp statements
dnl
define([rad_FLUSHLEFT],
 [changequote(`,')dnl
patsubst(`$1', `^[ 	]+')
changequote([,])])dnl

dnl rad_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is not `no'
dnl   $3 -- FALSE -- what to do otherwise; defaults to `:'
dnl
AC_DEFUN([rad_RESULT_ACTIONS], [
[if test "$$1" != "" -a "$$1" != no; then
  ]ifelse([$3], ,
          [AC_DEFINE(HAVE_]translit($2, [a-z ./<>], [A-Z___])[)],
          [$3])[
else
  ]ifelse([$4], , [:], [$4])[
fi]])dnl

dnl rad_CHECK_STRUCT_FIELD -- See if a structure has a particular field
dnl   $1 - NAME  -- name of structure
dnl   $2 - FIELD -- name of field to test
dnl   $3 - INCLS -- C program text to inculde necessary files for testing
dnl   $4 - TRUE  -- what to do if struct NAME has FIELD; defaults to 
dnl		    `AC_DEFINE(HAVE_NAME_FIELD)'
dnl   $5 - FALSE -- what to do if not; defaults to `:'
dnl
AC_DEFUN([rad_CHECK_STRUCT_FIELD], [
  define([rad_CVAR], [rad_cv_struct_]translit($1_$2, [A-Z], [a-z]))dnl
  AC_CACHE_CHECK([whether struct $1 has $2 field], rad_CVAR,
    AC_TRY_COMPILE(rad_FLUSHLEFT([$3]),
      [struct $1 rad_x; int rad_y = sizeof rad_x.$2;],
      rad_CVAR[=yes], rad_CVAR[=no]))
  rad_RESULT_ACTIONS(rad_CVAR, [$1_$2], [$4], [$5])dnl
  undefine([rad_CVAR])])dnl
