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
    AWKFLAGS="-vVALUE=$1 -vRESULT=8 -vSEARCH=9"	
else
    AWKFLAGS="-vVALUE=$1 -vRESULT=8 -vSEARCH=1"
fi 

IPADDR=`radwho -l -e:NULL: |
 AWK  $AWKFLAGS '$SEARCH==VALUE { if ($RESULT != ":NULL:") print $RESULT; exit }'`

if [ x"$IPADDR" = x"" ]; then
    echo "user $1 is not online"
    exit 1
fi
ping $IPADDR 
	     
