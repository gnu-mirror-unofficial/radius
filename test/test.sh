#! /bin/sh
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# $Id$

if expr ${SOURCEDIR:?} : '\..*' 2>/dev/null 1>&2; then
	SOURCEDIR="`pwd`/$SOURCEDIR"
fi
if expr ${BUILDDIR:?} : '\..*' 2>/dev/null 1>&2; then
	BUILDDIR="`pwd`/$BUILDDIR"
fi

if [ ! -f raddb/config.in ]; then
    cp -r ${SOURCEDIR}/test/raddb .
fi
EXPR=`./findport -c2 -s1644 "-fs/@AUTH_PORT@/%d/;s/@ACCT_PORT@/%d/"`
sed $EXPR raddb/config.in > raddb/config
sed $EXPR raddb/radctl.rc.in > raddb/radctl.rc

[ -d log ] || mkdir log
[ -d acct ] || mkdir acct
cat /dev/null > log/radwtmp
cat /dev/null > log/radutmp
RADSCM_BOOTPATH=${SOURCEDIR}/radscm \
  ../radscm/radscm --debug --directory raddb \
                   -s ${SOURCEDIR}/test/test.scm \
                    --build-dir $BUILDDIR

