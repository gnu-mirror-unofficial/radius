changequote(%,@)dnl
#! /bin/sh
# $Id$

RADOPT=
GREPOPT=
VAR=RADOPT

# collect arguments for radwho
while [ $# -ne 0 ]; 
do
	case $1 in
		--)	VAR=GREPOPT # collect grep arguments 
			%shift@;;
		-*) 	eval $VAR=\"\$$VAR $1\"
			%shift@;;
		*)	break;;
	esac
done

if [ $# -eq 0 ]; then
	echo "usage: radgrep [radwho-options] [-- grep-options] regexp" >&2
	exit 1
fi
radwho $RADOPT | grep $GREPOPT $*
