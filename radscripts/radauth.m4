include(SRCDIR/radscripts.m4)dnl
#! BINDIR/radtest -S
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

send auth 1 User-Name = $usr \
            Password = $pwd \
            NAS-Port-Id = $pid
expect 2
