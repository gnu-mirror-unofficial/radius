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
AC_DEFUN(rad_CHECK_INADDR_LOOPBACK,
  [
    AC_MSG_CHECKING(for INADDR_LOOPBACK)
    AC_CACHE_VAL(rad_cv_decl_inaddrloopback,[
      AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
                   ],[
  INADDR_LOOPBACK;
                   ],
                   rad_cv_decl_inaddrloopback=yes,
                   rad_cv_decl_inaddrloopback=no)])
    if test "$rad_cv_decl_inaddrloopback" = yes; then
      AC_MSG_RESULT(found)
    else
      AC_MSG_RESULT([no])
      AC_DEFINE_UNQUOTED(INADDR_LOOPBACK,0x7f000001)
    fi])
