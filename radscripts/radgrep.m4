changequote(%,@)dnl
#! /bin/sh
# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
