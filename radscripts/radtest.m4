#! /bin/sh
# $Id$
include(SRCDIR/radscripts.m4)dnl

ifdef(%GUILE@,
BINDIR/radscm --debug -s DATADIR/session.scm $*,
%cat - <<EOF
Sorry, Guile libraries are not installed on your system.
Please install them, then reconfigure and recompile Radius.
EOF
@)
