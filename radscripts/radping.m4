#! /bin/sh
# $Id$
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
    FORMAT="-oclid:20,ip:24"
else
    FORMAT="-ologin:20,ip:24"
fi 

IPADDR=`radwho $FORMAT -e:NULL: |
 AWK -vVALUE=$1 '$1==VALUE { if ($2 != ":NULL:") print $2; exit }'`

if [ x"$IPADDR" = x"" ]; then
    echo "user $1 is not online"
    exit 1
fi
ping $IPADDR 
	     
