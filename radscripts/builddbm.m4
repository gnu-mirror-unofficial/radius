include(SRCDIR/radscripts.m4)dnl
#! /bin/sh
# NOEDIT
#
# This file is part of GNU Radius.
# Copyright (C) 2001,2004 Free Software Foundation, Inc.
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

case "$1" in
    OPT_HELP) echo "usage: $0"
              exit 0;;
    OPT_VERSION) echo "$0: PACKAGE_STRING"
              exit 0;;
esac

SBINDIR/radiusd -mb $*

# End of builddbm.m4
