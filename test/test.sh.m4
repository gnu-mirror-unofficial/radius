#! /bin/sh
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001 Sergey Poznyakoff
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# $Id$

changequote([,])
PROG=$0
[SOURCEDIR]=SOURCEDIR
[BUILDDIR]=BUILDDIR
RADTEST=
RADIUSD=
DRIVER=
PROXY=0
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
    --proxy)
        PROXY=1; [shift];;
    --zero-logs)
	ZERO_LOGS=1; [shift];;
    *)
	echo "$PROG: wrong switch ($1)" >&2
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
if test ! -f proxy/config.in ; then
    cp -r ${[SOURCEDIR]}/test/proxy .
fi

EXPR=`./findport -c4 -s1644 "-fs^@AUTH_PORT@^%d^;\
s^@ACCT_PORT@^%d^;\
s^@PROXY_AUTH_PORT@^%d^;\
s^@PROXY_ACCT_PORT@^%d^;\
s^@USER@^%u^;\
s^@[BUILDDIR]@^$[BUILDDIR]^;\
s^@GUILE@^$GUILE^"`

make_raddb() {
    NAME=$1
    [shift]
    for file in $*
    do
        sed $EXPR $NAME/${file}.in > $NAME/$file
    done
    [[ -d $NAME/log ]] || mkdir $NAME/log
    [[ -d $NAME/acct ]] || mkdir $NAME/acct
    if [[ x"$ZERO_LOGS" != x ]]; then
	for file in radwtmp radutmp radius.log radius.info radius.debug radius.stderr 
	do
	    cat /dev/null > $NAME/log/$file
	done
    fi    
}

make_raddb raddb config client.conf users acct.scm realms
make_raddb proxy client.conf config realms

drv_guile() {
    RADSCM_BOOTPATH=${[SOURCEDIR]}/radscm \
      ../radscm/radscm --debug --directory raddb \
                       -s ${[SOURCEDIR]}/test/guile/test.scm \
                       --build-dir $[BUILDDIR]
}

stop_server() {
    for dir in $*
    do
        if test -r $dir/radiusd.pid; then
            kill -TERM `cat $dir/radiusd.pid`
            sleep 2
            if test -r $dir/radiusd.pid ; then
                kill -KILL `cat $dir/radiusd.pid` 	     
            fi
        fi
    done
}

LOCAL_CONF=$[BUILDDIR]/test/raddb
PROXY_CONF=$[BUILDDIR]/test/proxy

drv_dejagnu() {
    $RADIUSD -d $LOCAL_CONF \
             -l $LOCAL_CONF/log \
	     -a $LOCAL_CONF/acct \
	     -P $LOCAL_CONF
    if test $PROXY -ne 0; then
        $RADIUSD -d $PROXY_CONF \
                 -l $PROXY_CONF/log \
	         -a $PROXY_CONF/acct \
	         -P $PROXY_CONF
	CONF=$PROXY_CONF
    else
        CONF=$LOCAL_CONF
    fi
    trap "stop_server $LOCAL_CONF $PROXY_CONF" 1 3 15
    sleep 5
    $RADTEST -d $CONF 2>/tmp/radtest.err
    stop_server $LOCAL_CONF $PROXY_CONF
}	     

case $DRIVER in
    guile)   drv_guile;;
    dejagnu) drv_dejagnu;;
    *)       drv_guile;;
esac    
