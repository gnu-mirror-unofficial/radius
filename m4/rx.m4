## $Id$

## Based on Jim Meyering's jm_INCLUDED_REGEX:
AC_DEFUN(RA_REPLACE_REGEX,
  [
    AC_ARG_WITH(included-regex,
                [  --without-included-regex don't compile regex; this is the default on
                          systems with version 2 of the GNU C library
                          (use with caution on other system)],
		[ra_with_regex=$withval],
		[ra_with_regex=x]) 

    if test "$ra_with_regex" = x; then
      # Default is to use the included regex.c.
      ac_use_included_regex=yes

      # However, if the system regex support is good enough that it passes 
      # the following run test, then default to *not* using the included
      # regex.c.
      # If cross compiling, assume the test would fail and use the included
      # regex.c.  The first failing regular expression is from `Spencer ere
      # test #75' in grep-2.3.
      AC_CACHE_CHECK([for working re_compile_pattern],
	  	      ra_cv_func_working_re_compile_pattern,
        AC_TRY_RUN(
	  changequote(<<, >>)dnl
	  <<
#include <stdio.h>
#include <regex.h>
	  int
	  main ()
	  {
	    static struct re_pattern_buffer regex;
	    const char *s;
	    re_set_syntax (RE_SYNTAX_POSIX_EGREP);
	    /* Add this third left square bracket, [, to balance the
	       three right ones below.  Otherwise autoconf-2.14 chokes.  */
	    s = re_compile_pattern ("a[[:]:]]b\n", 9, &regex);
	    /* This should fail with _Invalid character class name_ error.  */
	    if (!s)
	      exit (1);

	    /* This should succeed, but doesn't for e.g. glibc-2.1.3.  */
	    s = re_compile_pattern ("{1", 2, &regex);

	   exit (s ? 1 : 0);
	  }
	  >>,
	  changequote([, ])dnl

	  ra_cv_func_working_re_compile_pattern=yes,
	  ra_cv_func_working_re_compile_pattern=no,
	  dnl When crosscompiling, assume it's broken.
	  ra_cv_func_working_re_compile_pattern=no))

      if test $ra_cv_func_working_re_compile_pattern = yes; then
         ac_use_included_regex=no
      fi
      ra_with_regex=$ac_use_included_regex
    fi
    if test "$ra_with_regex" = yes; then
      AC_DEFINE(WITH_INCLUDED_REGEX, 1,
                [Define if the included regex is to be used])
      AC_LIBOBJ([rx])
    fi
 ]
)
