include(SRCDIR/radscripts.m4)dnl
#! /bin/sh
# NOEDIT
# 
# This file is part of GNU Radius.
# Copyright (C) 2001,2003,2004 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

RADOPT=
GREPOPT=
VAR=RADOPT

usage() {
    echo "usage: radgrep [radwho-options] [-- grep-options] regexp" 
    exit ${1:-0}
}

# collect arguments for radwho
while TEST($# -ne 0); 
do
  case $1 in
      OPT_HELP) usage;;
      OPT_VERSION)
                echo "$0: PACKAGE_STRING"
                exit 0;;
      --)	VAR=GREPOPT # collect grep arguments 
                SHIFT;;
      -*) 	eval $VAR=\"\$$VAR $1\"
                SHIFT;;
      *)	break;;
  esac
done

if TEST($# -eq 0); then
	usage 1 >&2
fi
radwho $RADOPT | grep $GREPOPT $*
# End of radgrep.m4
