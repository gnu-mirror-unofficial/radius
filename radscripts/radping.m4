#! /bin/sh
# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
include(SRCDIR/radscripts.m4)dnl

PATH=$PATH:/sbin:/usr/sbin

usage() {
    echo "usage: radping login"
    echo "       radping -c caller_id"
    exit 1
}

set -- `GETOPT "c" $*`
while [ $# -ne 0 ]; 
do
	case $1 in
	-c) 	
		CALLERID=1
		SHIFT;;
	--)	SHIFT
		break;;
	*)	usage;;
	esac
done

if [ $# != 1 ]; then
    usage
fi

if [ "$CALLERID" = "1" ]; then
    FORMAT="-oclid:20,ip:16"
else
    FORMAT="-ologin:20,ip:16"
fi 

IPADDR=`radwho -n $FORMAT -e:NULL: |
 AWK -vVALUE=$1 '$1==VALUE { if ($2 != ":NULL:") print $2; exit }'`

if [ x"$IPADDR" = x"" ]; then
    echo "user $1 is not online"
    exit 1
fi
ping $IPADDR 
	     
