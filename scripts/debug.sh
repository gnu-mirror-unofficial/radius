#! /bin/sh
ID='$Id$'
ANCHOR="#define RADIUS_MODULE"
PROGNAME=$0
DEBUGMOD=debugmod.c
NODEBUG=include/nodebug.h
MODNUM=0
TOPDIR=`pwd`

if [ $# -le 3 ]; then
	echo "usage: $PROGNAME skel deflib dirs"
	exit 1
fi

if [ x$MAKE = x ]; then
	MAKE=make
fi

SKEL=$1
shift
DEFLIBDIR=$1
shift
DIRS="$*"

if [ x$TMP != x ]; then
	if [ -d $TMP ]; then
		TF=$TMP
	fi
fi
if [ x$TF = x ]; then
	if [ x$TEMP != x ]; then
		TF=$TMP
	fi
fi
if [ x$TF = x ]; then
	TF=/tmp
fi
TF=${TF}/debug.$$

# Create a debugmod.c file
#
debugmod() {
(
 cat - <<EOF
/* This file is generated automatically.
 * Generator: $PROGNAME $ID
 * Skeleton:  $SKEL
 */

EOF
 m4 -DMODNUM=$MODNUM ${TF}.lib $TF ${TOPDIR}/$SKEL
) > $DEBUGMOD
}

MODNUM=0
echo "$MODNUM" > ${TF}.modnum

# Process source files in the current directory
# usage:  process_sources <outfile> <filelist>
#    
process_sources() {
	FILE=$1
	shift
	for i in $*
	do
		if grep "^$ANCHOR" $i > /dev/null; then
			mv $i $i~
			sed -e "s/^\($ANCHOR\).*/\1 $MODNUM/" \
			    $i~ > $i
			echo "\t\"`basename $i`\", $MODNUM," >> $FILE
			MODNUM=`expr $MODNUM + 1`
		fi
	done
}


## First, process library directories
echo "divert(1)" > ${TF}.lib
for dir in $DIRS
do
	if [ -r $dir/Makefile ]; then
		(cd $dir; 
                 if $MAKE LIBLIST >/dev/null 2>/dev/null; then
			if [ -r .list ]; then
				echo "$dir"
				MODNUM=`cat ${TF}.modnum`
		 		process_sources ${TF}.lib `cat .list`
				echo $MODNUM > ${TF}.modnum
			        rm .list
			fi
		 fi)
	fi
done

MODSTART=`cat ${TF}.modnum`

## Now process all application directories
echo "divert(2)" > $TF
MODNUM=$MODSTART
(cd $DEFLIBDIR; debugmod) 

for dir in $DIRS
do
	if [ -r $dir/Makefile ]; then
		echo "divert(2)" > $TF
		MODNUM=$MODSTART
		(cd $dir; 
                 if $MAKE FILELIST >/dev/null 2>/dev/null; then
			if [ -r .list ]; then
		 		echo "$dir"
		 		process_sources $TF `cat .list`
			fi
		 fi
		 if [ $MODNUM -gt $MODSTART ]; then 
			debugmod 
		 fi)
	fi
done


rm $TF ${TF}.lib ${TF}.modnum

