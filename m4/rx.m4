## $Id$

AC_DEFUN(rad_LIB_REGEX,
[
   AC_CHECK_FUNCS(regcomp)
   if test $ac_cv_func_regcomp = no; then
       LIBOBJS="$LIBOBJS rx.o"
   fi])

   