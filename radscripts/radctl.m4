#! /bin/sh
# $Id$
# This file is part of GNU Radius.
# Copyright (C) 2000,2003 Sergey Poznyakoff
#
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
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
include(SRCDIR/radscripts.m4)dnl

PATH=/bin:/usr/bin:/usr/ucb:$PATH; export PATH
[PS]="PS"
[PIDFILE]=PIDFILE
[PROGNAME]=PROGNAME

usage() {
	cat - <<EOF
usage: $0 {start|stop|restart|reload|which|dump}
EOF
	exit 0
}

start() {
	$[PROGNAME] ${1} && {
		sleep 5
		if TEST(-r $[PIDFILE]) ; then
			echo "RADIUS server started"
		else
			echo "can't start RADIUS server"
		fi
	}
}

stop() {
	TEST($RUNNING -eq 1) && {
		echo "sending TERM to RADIUS server ($PID)"
		kill -TERM $PID && sleep 5
		TEST(-r $[PIDFILE]) && {
			echo "radiusd ($PID) is still running. Sending KILL"
			kill -9 $PID && sleep 5
		}
	}
	rm -f $[PIDFILE]
}

chan_signal() {
	case $1 in
		reload) 
                        TEST($RUNNING -eq 0) && {
                                echo $PROCESS
                                exit 1
                        }
			kill -HUP  $PID && echo "Reloading configs";;
		start)
			TEST($RUNNING -eq 1) && {
				echo "$0: start: radiusd (pid $PID) already running"
				exit 1
			}
			rm -f $[PIDFILE]
			SHIFT
			start $*;;
		stop)   stop;;

		which)  echo $PROCESS;;

		restart)
			stop
			SHIFT
			start $*;;

		dump)
                        TEST($RUNNING -eq 0) && {
                                echo $PROCESS
                                exit 1
                        }
			kill -USR2 $PID && echo "Dumping users database";;
			
		*)	usage;;
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

