## $Id$

AC_DEFUN(rad_LIB_REGEX,
[
 AC_CACHE_CHECK([for -lrx], rad_cv_lib_rx,
  [
   AC_CHECK_FUNCS(regcomp)
   if test $ac_cv_func_regcomp = no; then
     # regcomp is not in the default libraries.  See if it's in some
     # other.
     libname=no
     for lib in rx regex; do
       AC_CHECK_LIB($lib, regcomp,
                    [libname=$lib; break])
     done
     if test $libname != no; then 
       LIBS="$LIBS $libname"
     else
       LIBOBJS="$LIBOBJS rx.o"
     fi
   fi])])

   