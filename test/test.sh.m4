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

changequote([,])
PROG=$0
[SOURCEDIR]=SOURCEDIR
[BUILDDIR]=BUILDDIR
RADTEST=
RADIUSD=
DRIVER=
GUILE="#"

while test $# -gt 0 
do
    case $1 in
    --srcdir)
	[SOURCEDIR]=$2; [shift] 2;;
    --builddir)
	[BUILDDIR]=$2; [shift] 2;;
    --radiusd)
	RADIUSD=$2; [shift] 2;;
    --radtest)
	RADTEST=$2; [shift] 2;;
    --driver)
	DRIVER=$2; [shift] 2;;
    --guile)
        GUILE=""; [shift];;
    *)
	echo "$PROG: wrong switch" >&2
	exit 1;;
    esac
done

if expr ${[SOURCEDIR]:?} : '\..*' 2>/dev/null 1>&2; then
    [SOURCEDIR]="`pwd`/$[SOURCEDIR]"
fi
if expr ${[BUILDDIR]:?} : '\..*' 2>/dev/null 1>&2; then
    [BUILDDIR]="`pwd`/$[BUILDDIR]"
fi

if test "$RADTEST" = "" ; then
    RADTEST=$[BUILDDIR]/radtest/radtest
fi
if test "$RADIUSD" = "" ; then    
    RADIUSD=$[BUILDDIR]/radiusd/radiusd
fi
    
cd $[BUILDDIR]/test

if test ! -f raddb/config.in ; then
    cp -r ${[SOURCEDIR]}/test/raddb .
fi

EXPR=`./findport -c2 -s1644 "-fs^@AUTH_PORT@^%d^;\
s^@ACCT_PORT@^%d^;\
s^@USER@^%u^;\
s^@[BUILDDIR]@^$[BUILDDIR]^;\
s^@GUILE@^$GUILE^"`

for file in config client.conf users acct.scm
do
    sed $EXPR raddb/${file}.in > raddb/$file
done

[[ -d log ]] || mkdir log
[[ -d acct ]] || mkdir acct
for file in log/radwtmp log/radutmp log/radius.log log/radius.info log/radius.debug log/radius.stderr 
do
    cat /dev/null > $file
done    

drv_guile() {
    RADSCM_BOOTPATH=${[SOURCEDIR]}/radscm \
      ../radscm/radscm --debug --directory raddb \
                       -s ${[SOURCEDIR]}/test/guile/test.scm \
                       --build-dir $[BUILDDIR]
}

drv_dejagnu() {
    $RADIUSD -d $[BUILDDIR]/test/raddb \
             -l $[BUILDDIR]/test/log \
	     -a $[BUILDDIR]/test/acct \
	     -P $[BUILDDIR]/test/log
    $RADTEST -d $[BUILDDIR]/test/raddb 2>/tmp/radtest.err
    kill -TERM `cat $[BUILDDIR]/test/log/radiusd.pid`
    sleep 5
    if test -r $[BUILDDIR]/test/log/radiusd.pid ; then
        kill -KILL `cat $[BUILDDIR]/test/log/radiusd.pid` 	     
    fi
}	     

case $DRIVER in
    guile)   drv_guile;;
    dejagnu) drv_dejagnu;;
    *)       drv_guile;;
esac    
