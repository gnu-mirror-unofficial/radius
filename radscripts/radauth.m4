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
