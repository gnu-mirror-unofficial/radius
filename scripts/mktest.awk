## This file is part of GNU RADIUS.
## Copyright (C) 2001, Sergey Poznyakoff
##
## This file is free software; as a special exception the author gives
## unlimited permission to copy and/or distribute it, with or without
## modifications, as long as this notice is preserved.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

BEGIN {
	INCR = 1;
        num = 0;
	if (!CMD) CMD = "cp"
	if (!SRCDIR)
		SRCDIR="."
	if (!DSTDIR) {
		if (match(SRCDIR,"/s\..*")) {
			DSTDIR=substr(SRCDIR, 1, RSTART) substr(SRCDIR,RSTART+3)
		}
	}
	printf("if [ ! -d %s ]; then mkdir %s; fi\n", DSTDIR, DSTDIR)
	printf("rm -f %s/[0-9][0-9][0-9]*.exp\n", DSTDIR)
}
/#.*/ { next }
NF==0 { next }
/+/ { INCR = $2; next }
{ printf("%s %s/%s %s/%03d%s\n", CMD, SRCDIR, $1, DSTDIR, num, $1); num += INCR }

	

