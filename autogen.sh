#! /bin/sh

aclocal -I m4 &&
 libtoolize --automake -c &&
 autoheader &&
 automake -a -c &&
 autoconf
