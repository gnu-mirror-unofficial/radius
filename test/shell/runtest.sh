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

base_dir=.

if [ "x$AWK" = x ]; then
    AWK=awk
fi    

error() {
    echo "$*" >&2
}

if [ "x$RADIUSD" = x ]; then
    RADIUSD=`cd $base_dir/../..; pwd`/radiusd/radiusd
fi
if [ ! -x $RADIUSD ]; then
    error "Can't find executable ($RADIUSD)"
    exit 1
fi
if [ "x$RADTEST" = x ]; then
    RADTEST=`expr "$RADIUSD" : '\(.*\)/radiusd/radiusd'`/radtest/radtest
fi    
if [ ! -x $RADTEST ]; then
    error "Can't find executable ($RADTEST)"
    exit 1
fi

radiusd_version() {
    TMP=/tmp/$$
    $RADIUSD --version |
     while read LINE
     do
	case "$LINE" in
	*version*)
	    echo export RADIUSD_VERSION=`expr "$LINE" : '.*GNU Radius version \([0-9.]*\).*'`
	    ;;
	*flags:*)
	    for var in `expr "$LINE" : '.*Compilation flags: \(.*\)'`
	    do
		echo "export $var=1"
	    done	
	    ;;
	*) ;;
	esac
     done > $TMP
     . $TMP
     rm $TMP
}

radiusd_version

SHELL="$base_dir/../test.sh --radiusd $RADIUSD --radtest $RADTEST --driver dejagnu"

if [ "x$USE_SERVER_GUILE" = "x1" ]; then
    SHELL="$SHELL --guile"
fi

VERBOSE=0
TESTLIST=""
if [ "x$TOOL" = "x" ]; then
    TOOL=radiusd
fi    
TESTFILEMASK="*.sh"
START_SH=001Start.sh

while [ $# -gt 0 ]
do
    case "$1" in
    --tool)
	TOOL=`expr "$1" : '.*=\(.*\)'`
	shift;;
    --verbose|-v)
	VERBOSE=`expr $VERBOSE + 1`
	shift;;
    *)  TESTLIST="$TESTLIST $1"
	shift;;
    esac	
done

DIRLIST=`find $base_dir -name "$TOOL*" -type d -print`
if [ "x$DIRLIST" = x ]; then
    error "No directories for tool \"$TOOL\" found"
    exit 1
fi

runtest() {
    if [ -r $dir/$START_SH ]; then
    	OPTIONS=`sh $dir/$START_SH`
    else
	OPTIONS=
    fi
    sh | 
    $SHELL $OPTIONS     
}

(if [ x"$TESTLIST" != "x" ]; then
    for dir in $DIRLIST
    do
	for file in $TESTLIST
	do
	    find $dir -name $file -exec cat {} \; 
	done | runtest $dir
    done
else
    for dir in $DIRLIST
    do
	find $dir -name "$TESTFILEMASK" -exec cat {} \; | runtest $dir
    done
fi) |
 $AWK -vVERBOSE=$VERBOSE '
    /:[0-9]*:.*/ {
	test_total++;
	n = split($0,arg,":")
	ntest = arg[2]
	if (n == 4)
	    pattern = arg[3]
	else
	    pattern = "PASS"
	fi
	state = 1
	if (VERBOSE)
	    print "Test " ntest
	next
    }
    /UNSUPPORTED/ {
	unsupp++;
	state = 0;
	if (VERBOSE)
	    print "UNSUPPORTED"
	next
    }
    state == 0 { print }
    state == 1 { if (VERBOSE) print $0 }
    state == 1 && /PASS/ { pass++; state = 0; next }
    state == 1 && /FAIL/ { fail++; state = 0; next }
    state == 1 {
	if (index($0, pattern))
	    pass++;
	else
	    fail++;
	state = 0;
	next
    }   
    END {
     	    print "# of expected passes " pass+0
	    print "# of failed tests " fail+0
	    print "# of unsupported tests " unsupp+0
	    print "# total " test_total
    }'

