dnl rad_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is `yes'
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



