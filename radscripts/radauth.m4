#! /bin/sh
# $Id$
include(SRCDIR/radscripts.m4)dnl

PROGNAME=$0

usage() {
	cat - <<EOF
usage: $PROGNAME [-v] login password
EOF
}

if [ $# -lt 1 ]; then
	usage
	exit 0
fi
[ x"$1" = x"-v" ] && { V=--verbose; SHIFT; }
[ x"$1" = x"--verbose" ] && { V=--verbose; SHIFT; }
 
if [ $# -ne 2 ]; then
	usage
	exit 0;
fi

BINDIR/radscm -s DATADIR/session.scm $V --login $1 --passwd $2 --auth
