include(SRCDIR/radscripts.m4)dnl
#! /bin/sh
# NOEDIT
#
# This file is part of GNU Radius.
# Copyright (C) 2000, 2003, 2005, 2007 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

PATH=/bin:/usr/bin:/usr/ucb:$PATH; export PATH
[PS]="PS"
[PIDFILE]=PIDFILE
[PROGNAME]=PROGNAME

usage() {
    cat - <<EOF
usage: $0 {start|stop|restart|reload|which|status|dump}
EOF
    exit ${1:-0}
}


# Wait up to 5 seconds for the status of the pidfile to change. 
# Usage: pidfile_status 1	Wait until pidfile is available
#        pidfile_status 0	Wait until pidfile is not available
# Returns true if the status did change.
pidfile_status()
{
    N=1
    while TEST($N -lt 6)
    do
	test -r $[PIDFILE]
	TEST($? -ne $1) && return 0
        sleep 1
	N=ARITH($N + 1)
    done
    return 1
}

start() {
    rm -f $[PIDFILE]
    if $[PROGNAME] ${1}; then
        if pidfile_status 1; then
	    echo "RADIUS server started (`cat $[PIDFILE]`)"
	else
	    echo "Cannot start RADIUS server"
	fi
    fi
}

stop() {
    if TEST($RUNNING -eq 1); then
	echo "Sending TERM to RADIUS server ($PID)"
	kill -TERM $PID || exit 1
	if pidfile_status 0; then
	    echo "Stopped RADIUS server ($PID)"
	else
	    echo "radiusd ($PID) is still running. Sending KILL"
	    kill -9 $PID
	    rm -f $[PIDFILE]
	fi
    fi
}

chan_signal() {
    case $1 in
	OPT_HELP)
	   usage;;
	      
	OPT_VERSION)
           echo "$0: PACKAGE_STRING"
           exit 0;;
    
	reload) 
           if TEST($RUNNING -eq 0); then
	       echo "$PROCESS"
	       exit 1
	   fi
	   kill -HUP  $PID && echo "Reloading configs";;
	   
	start)
	   if TEST($RUNNING -eq 1); then
	       echo "$0: start: radiusd (pid $PID) already running"
	       exit 1
	   fi
	   rm -f $[PIDFILE]
	   SHIFT
	   start $*;;
	   
	stop)
	   stop;;

	which|status)
	   echo "$PROCESS";;

	restart)
	   stop
	   SHIFT
	   start $*;;

	dump)
	   if TEST($RUNNING -eq 0); then
	       echo "$PROCESS"
	       exit 1
	   fi
	   kill -USR2 $PID && echo "Dumping users database";;
			
	*) usage >&2;;
    esac

    exit 0
}

if TEST(-f $[PIDFILE]); then
    PID=`cat $[PIDFILE]`
    PROCESS=`$[PS] -p $PID | sed -n '2p'`
    RUNNING=1
    TEST(`echo $PROCESS | wc -w` -ne 0) || {
	PROCESS="radiusd (pid $PID?) not running"
	RUNNING=0
    }
else
    PROCESS="radiusd not running"
    RUNNING=0
fi

if TEST(x"$1" = x"--debug"); then
    DEBUG=$1
    SHIFT
fi	    

if TEST(x"$1" = x"-s" -o x"$1" = x"--signal"); then
    SHIFT 
fi
chan_signal $*

