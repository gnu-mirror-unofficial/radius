#! /bin/sh
# $Id$
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
