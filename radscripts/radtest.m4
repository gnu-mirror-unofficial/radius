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
