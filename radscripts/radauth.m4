#! /bin/sh
# $Id$
include(SRCDIR/radscripts.m4)dnl

PROGNAME=$0

usage() {
	cat - <<EOF
usage: $PROGNAME [options] login password
Options are:
EOF
RADTEST -h 2>&1 | sed -e '1,3d'
}

set -- `GETOPT "a:d:hlp:qr:s:t:vx:V" $*`
while [ $# -ne 0 ]; 
do
	case $1 in
	-a|-d|-p|-r|-s|-t|-x)
		RADTEST_OPTS="$RADTEST_OPTS $1 $2"
		SHIFT 2;;
	-l|-q|-v|-V)
		RADTEST_OPTS="$RADTEST_OPTS $1"
		SHIFT;;
	--)	SHIFT
		break;;
	*)	usage
		exit 1;;
	esac
done

if [ $# -ne 2 ]; then
	usage
	exit 1
fi

LOGIN=\"$1\"
PASSWD=\"$2\"

RADTEST $RADTEST_OPTS <<EOF
	auth_packet = { 
            User-Name = $LOGIN
	    Password = $PASSWD
	};
	send auth 1 \$auth_packet;
	expect 2 "rejected (" \$REPLY_CODE "); Reply-Message = " \$REPLY[Reply-Message];
	print "Authentity confirmed, reply pairs: " \$REPLY;
EOF

