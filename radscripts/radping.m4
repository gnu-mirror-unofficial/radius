include(SRCDIR/radscripts.m4)dnl
#! /bin/sh
# NOEDIT
#
# This file is part of GNU Radius.
# Copyright (C) 2001,2003 Free Software Foundation, Inc.
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

PATH=$PATH:/sbin:/usr/sbin

usage() {
    echo "usage: radping login"
    echo "       radping -c caller_id"
    exit ${1:-0}
}

while TEST($# -ne 0); 
do
  case $1 in
      OPT_HELP) usage;;
      OPT_VERSION)
                echo "$0: PACKAGE_STRING"
                exit 0;;
      -c)       CALLERID=1
	        SHIFT;;
      *)        break;;
  esac
done

if TEST($# != 1); then
    usage 1 >&2
fi

if TEST("$CALLERID" = "1"); then
    FORMAT="(clid)(tab)(framed-address)"
else
    FORMAT="(login)(tab)(framed-address)"
fi 

IPADDR=`radwho -n -o $FORMAT -e:NULL: |
 AWK -vVALUE=$1 '$1==VALUE { if ($2 != ":NULL:") print $2; exit }'`

if TEST(x"$IPADDR" = x""); then
    echo "user $1 is not online"
    exit 1
fi
ping $IPADDR 
	     
# End of radping.m4
