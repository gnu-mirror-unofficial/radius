dnl This file is part of GNU Radius.
dnl Copyright (C) 2001,2003,2007 Free Software Foundation, Inc.
dnl
dnl Written by Sergey Poznyakoff
dnl
dnl GNU Radius is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl GNU Radius is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with GNU Radius; if not, write to the Free Software Foundation,
dnl Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
dnl
AC_DEFUN([RA_CHECK_INADDR_LOOPBACK],
  [
    AC_MSG_CHECKING(for INADDR_LOOPBACK)
    AC_CACHE_VAL(ra_cv_decl_inaddrloopback,[
      AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
                   ],[
  INADDR_LOOPBACK;
                   ],
                   ra_cv_decl_inaddrloopback=yes,
                   ra_cv_decl_inaddrloopback=no)])
    if test "$ra_cv_decl_inaddrloopback" = yes; then
      AC_MSG_RESULT(found)
    else
      AC_MSG_RESULT([no])
      AC_DEFINE_UNQUOTED(INADDR_LOOPBACK,0x7f000001,
                         [System headers should have defined this])
    fi])
