## This file is part of GNU Radius.
## Copyright (C) 2001, 2006, 2010, 2013 Free Software Foundation, Inc.
##
## Written by Sergey Poznyakoff
##
## This file is free software; as a special exception the author gives
## unlimited permission to copy and/or distribute it, with or without
## modifications, as long as this notice is preserved.
##
## GNU Radius is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

BEGIN {
        print "/* -*- buffer-read-only: t -*- vi: set ro:"
	print " * THIS FILE IS GENERATED AUTOMATICALLY.  PLEASE DO NOT EDIT."
	print " * $Id$"
	print " *"
	for (i = 1; i < ARGC; i++)
		print " * Source file: " ARGV[i]
        print " */"
}

/--.*/ {
	print substr($0, 3);
	next;
}

NF == 3 && $1 == "=" {
        ## Fixed oid
	print "#define MIB_" $2 " " $3
	n = split($3, a, ",")
	print "#define LEN_" $2 " " n
	print "#define MIB_KEY_" $2 " " a[n]

	mib_name[mib_count++] = $2  
	  
	next
}

NF == 3 && $1 == "~" {
        ## Variable oid
	print "#define MIB_" $2 " " $3 ",-1"
	n = split($3, a, ",")
	print "#define LEN_" $2 " " n+1
	print "#define MIB_KEY_" $2 " " a[n]

	mib_name[mib_count++] = $2  
	  
	next
}

END {
        print
        print "#ifdef SERVER"
        for (i = 0; i < mib_count; i++) 
                print "subid_t oid_" mib_name[i] "[] = { LEN_" mib_name[i] ", MIB_" mib_name[i] " };"
        print "#else"
        for (i = 0; i < mib_count; i++) 
                print "extern subid_t oid_" mib_name[i] "[];"
        print "#endif"
}
