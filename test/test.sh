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

PROG=$0
RADTEST=
RADIUSD=
DRIVER=

while [ $# -gt 0 ]
do
    case $1 in
    --srcdir)
	SOURCEDIR=$2; shift 2;;
    --builddir)
	BUILDDIR=$2; shift 2;;
    --radiusd)
	RADIUSD=$2; shift 2;;
    --radtest)
	RADTEST=$2; shift 2;;
    --driver)
	DRIVER=$2; shift 2;;
    *)
	echo "$PROG: wrong switch" >&2
	exit 1;;
    esac
done

if expr ${SOURCEDIR:?} : '\..*' 2>/dev/null 1>&2; then
    SOURCEDIR="`pwd`/$SOURCEDIR"
fi
if expr ${BUILDDIR:?} : '\..*' 2>/dev/null 1>&2; then
    BUILDDIR="`pwd`/$BUILDDIR"
fi

if [ "$RADTEST" = "" ]; then
    RADTEST=$BUILDDIR/radtest/radtest
fi
if [ "$RADIUSD" = "" ]; then    
    RADIUSD=$BUILDDIR/radiusd/radiusd
fi
    
cd $BUILDDIR/test

if [ ! -f raddb/config.in ]; then
    cp -r ${SOURCEDIR}/test/raddb .
fi
EXPR=`.//findport -c2 -s1644 "-fs/@AUTH_PORT@/%d/;s/@ACCT_PORT@/%d/"`
sed $EXPR raddb/config.in > raddb/config
sed $EXPR raddb/client.conf.in > raddb/client.conf

[ -d log ] || mkdir log
[ -d acct ] || mkdir acct
cat /dev/null > log/radwtmp
cat /dev/null > log/radutmp

drv_guile() {
    RADSCM_BOOTPATH=${SOURCEDIR}/radscm \
      ../radscm/radscm --debug --directory raddb \
                       -s ${SOURCEDIR}/test/guile/test.scm \
                       --build-dir $BUILDDIR
}

drv_dejagnu() {
    $RADIUSD -d $BUILDDIR/test/raddb \
             -l $BUILDDIR/test/log \
	     -a $BUILDDIR/test/acct \
	     -P $BUILDDIR/test/log
    $RADTEST -d $BUILDDIR/test/raddb -xgram.y 2>/tmp/log
    kill -TERM `cat $BUILDDIR/test/log/radiusd.pid`
    sleep 5
    if [ -r $BUILDDIR/test/log/radiusd.pid ]; then
        kill -KILL `cat $BUILDDIR/test/log/radiusd.pid` 	     
    fi
}	     

case $DRIVER in
    guile)   drv_guile;;
    dejagnu) drv_dejagnu;;
    *)       drv_guile;;
esac    