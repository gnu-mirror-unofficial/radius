#! /bin/sh

if expr ${SOURCEDIR:?} : '\..*' 2>/dev/null 1>&2; then
	SOURCEDIR="`pwd`/$SOURCEDIR"
fi
if expr ${BUILDDIR:?} : '\..*' 2>/dev/null 1>&2; then
	BUILDDIR="`pwd`/$BUILDDIR"
fi

(cd ${BUILDDIR}/test;
 [ -d raddb ] || cp -r ${SOURCEDIR}/test/raddb .

 EXPR=`./findport -c3 -s1644 "-fs/@AUTH_PORT@/%d/;s/@ACCT_PORT@/%d/;s/@CNTL_PORT@/%d/"`
 sed $EXPR raddb/config.in > raddb/config
 sed $EXPR raddb/radctl.rc.in > raddb/radctl.rc

 [ -d log ] || mkdir log
 [ -d acct ] || mkdir acct
 cat /dev/null > log/radwtmp
 cat /dev/null > log/radutmp
 RADSCM_BOOTPATH=${SOURCEDIR}/radscm \
  ${BUILDDIR}/radscm/radscm --debug --directory raddb \
                             -s ${SOURCEDIR}/test/test.scm \
                             --build-dir $BUILDDIR
)
