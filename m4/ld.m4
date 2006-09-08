AC_DEFUN([RA_LD_VERSIONING],
 [AC_CACHE_CHECK([for ld --version-script],
                 [ra_cv_ld_version_script_option], [dnl

  cat > conftest.c <<EOF
int foo()
{
	return 0;
}
EOF

  cat > conftest.map <<EOF
VERS_1 {
        global: foo;
};

VERS_2 {
        global: foo;
} VERS_1;
EOF
  if AC_TRY_COMMAND([${CC-cc} $CFLAGS $LDFLAGS -shared
                              -o conftest.so conftest.c
                              -nostartfiles -nostdlib
                              -Wl,--version-script,conftest.map])
  then
    ra_cv_ld_version_script_option=yes
  else
    ra_cv_ld_version_script_option=no
  fi
  rm -f conftest*])
  AC_SUBST(VERSION_SCRIPT_OPTION)
  if test "$ra_cv_ld_version_script_option" = yes; then
    VERSION_SCRIPT_OPTION='-Wl,--version-script=$(VERSION_SCRIPT)'
  else
    VERSION_SCRIPT_OPTION=
  fi])



