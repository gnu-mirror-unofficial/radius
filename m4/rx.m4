## $Id$

AC_DEFUN(rad_LIB_REGEX,
[
   AC_ARG_WITH(included-regex,
	[  --with-included-regex        use regex functions supplied with the distribution],
	[LIBOBJS="$LIBOBJS rx.o"],
	[AC_CHECK_FUNCS(regcomp)
         if test $ac_cv_func_regcomp = no; then
            LIBOBJS="$LIBOBJS rx.o"
         fi])])

   