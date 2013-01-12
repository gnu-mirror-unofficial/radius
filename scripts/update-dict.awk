## This file is part of GNU Radius.
## Copyright (C) 2001, 2010, 2013 Free Software Foundation, Inc.
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
##

## This program converts the dictionary file of GNU Radius-1.1 or older
## to the new (v1.2) dictionary format, preserving any includes and new
## definitions. Notice, that it operates only on the main dictionary
## (raddb/dictionary).

## usage: update-dict.awk $(sysconfdir)/raddb/dictionary
##                        $(top_srcdir)/raddb/dictionary
##                        $(top_srcdir)/raddb/dict/standard
##   			  

# Process old raddb/dictionary and populate attribute tables.
ARGIND == 1 && NF >= 2 && $1 == "$INCLUDE" {
        include[$2] = 1;
}
ARGIND == 1 && $1 == "ATTRIBUTE" {
	attribute[$2] = $0
	attr_def[$2,"value"] = $3
	attr_def[$2,"type"] = $4
	attr_def[$2,"prop"] = $6
	attr_val[$3] = $2
}
ARGIND == 1 && $1 == "VALUE" {
	value[$2] = value[$2] "\n" $0
}
ARGIND == 1 { next }

# Process new style raddb/dictionary file. Comment/uncomment necessary
# includes.
ARGIND == 2 && /^\$INCLUDE/ {
	if ($2 == "dict/standard")
	        print
	else if (include[$2]) {
		print
		delete include[$2]
	} else
	        print "#" $0
	next
}
ARGIND == 2 && /^#\$INCLUDE/ {
	if (include[$2]) {
		print substr($0, 2)
		delete include[$2]
	} else
	        print
	next
}
ARGIND == 2 { print }

# Process standard dictionary and update attribute tables
ARGIND == 3 && $1 == "ATTRIBUTE" {
	if (attr_val[$3] && $2 != attr_val[$3]) {
		delete attribute[attr_val[$3]]
	        alias[$2] = attr_val[$3]
	}
	if (attr_def[$2,"value"]) {
		if (attr_def[$2,"value"] != $3 || attr_def[$2,"type"] != $4)
		     wrongdef[$2] = attribute[$2]
		else if (attr_def[$2,"prop"] != $6) 
		     property[$2] = attr_def[$2,"prop"]
	}
	delete attribute[$2]
	delete attr_def[$2,"value"]
	delete attr_def[$2,"type"] 
	delete attr_def[$2,"prop"] 
}
ARGIND == 3 && $1 == "VALUE" {
        delete value[$2]
}
ARGIND == 3 { next }

# Finally, output user-specific customizations
END {
	print "# User customizations"
	for (n in attribute)
		print attribute[n]
	print ""
	print "# Alternative properties. Uncomment these if you know what you're doing"
	for (n in property) {
		if (n != "User-Password" && n != "Password"\
		    && n != "CHAP-Password" && property[n] != "")
			print "# PROPERTY " n " " property[n]
	}
	print "# End of properties section"
        print ""
        print "# Alias section"
	for (n in alias)
		print "ALIAS " n " " alias[n]
        print ""
        print "# Values section"
	for (n in value)
		print value[n]
	print "# End of dictionary"
}

# End of update-dict.awk

