#! /bin/sh
# This file is part of GNU Radius.
# Copyright (C) 2004, 2006, 2010, 2013 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

cat - <<EOT
/* -*- buffer-read-only: t -*- vi: set ro: 
   THIS FILE IS GENERATED AUTOMATICALLY.  PLEASE DO NOT EDIT.
*/ 
EOT

for module
do
	echo "extern SQL_DISPATCH_TAB ${module}_dispatch_tab;"
done

cat - <<EOT
static SQL_DISPATCH_TAB *static_dispatch_tab[] = {
        NULL,
EOT

for module
do
	echo "	&${module}_dispatch_tab,"
done

echo "};"
echo '/* EOF */'
