#! /bin/sh
# $Id$
include(SRCDIR/radscripts.m4)dnl

if [ x$1 = x--debug ]; then
	DEBUG=$1
	SHIFT
fi

ifdef(%GUILE@,
BINDIR/radscm $DEBUG -s DATADIR/session.scm $*,
%cat - <<EOF
Sorry, Guile libraries are not installed on your system.
Please install them, then reconfigure and recompile Radius.
EOF
@)
