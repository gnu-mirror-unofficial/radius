#! /bin/sh
# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2000, Sergey Poznyakoff
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
include(SRCDIR/radscripts.m4)dnl

PATH=/bin:/usr/bin:/usr/ucb:$PATH; export PATH
%PS@="PS"
%PIDFILE@=PIDFILE
%PROGNAME@=PROGNAME

usage() {
	cat - <<EOF
usage: $0 {start|stop|restart|reload|dumpdb|status|which}
EOF
	exit 0
}

start() {
	$%PROGNAME@ ${1} && {
		sleep 5
		if [ -r $%PIDFILE@ ]; then
			echo "RADIUS server started"
		else
			echo "can't start RADIUS server"
		fi
	}
}

stop() {
	[ $RUNNING -eq 1 ] && {
		echo "sending TERM to RADIUS server ($PID)"
		kill -TERM $PID && sleep 5
		[ -r $%PIDFILE@ ] && {
			echo "radiusd ($PID) is still running. Sending KILL"
			kill -9 $PID && sleep 5
		}
	}
	rm -f $%PIDFILE@
}

chan_signal() {
	case $1 in
		start|stop|restart)
			;;
		*)	[ $RUNNING -eq 0 ] && {
				echo $PROCESS
				exit 1
			}
	esac

	case $1 in
		reload) kill -HUP  $PID && echo "Reloading configs";;
		status)	kill -USR1 $PID && echo "Dumping statistics";;
		dumpdb)	kill -INT  $PID && echo "Dumping Database";;
		start)
			[ $RUNNING -eq 1 ] && {
				echo "$0: start: radiusd (pid $PID) already running"
				continue
			}
			rm -f $%PIDFILE@
			SHIFT
			start $*;;
		stop)   stop;;

		which)  echo $PROCESS;;

		restart)
			stop
			SHIFT
			start $*;;

		*)	usage;;
	esac

	exit 0
}

ifdef(%GUILE@,
chan_socket() {
	BINDIR/radscm $DEBUG -s DATADIR/radctl.scm $*
})

if [ -f $%PIDFILE@ ]; then
	PID=`cat $%PIDFILE@`
	PROCESS=`$%PS@ -p $PID | sed -n '2p'`
	RUNNING=1
	[ `echo $PROCESS | wc -w` -ne 0 ] || {
		PROCESS="radiusd (pid $PID?) not running"
		RUNNING=0
	}
else
	PROCESS="radiusd not running"
	RUNNING=0
fi

if [ x"$1" = x"--debug" ]; then
	DEBUG=$1
	SHIFT
fi	    
ifdef(%GUILE@,
if [ x"$1" = x"-s" -o x"$1" = x"--signal" ]; then
	%SHIFT@ 
	chan_signal $*
else
	chan_socket $*
fi,
if [ "$1" = "-s" ]; then
	%SHIFT@
fi
chan_signal $*)



