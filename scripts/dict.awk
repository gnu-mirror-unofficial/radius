## This file is part of GNU Radius.
## Copyright (C) 2001,2004 Free Software Foundation, Inc.
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
## $Id$
## usage: awk -f dict.awk <dictionary.file>
## or, to preserve whitespace in the output:  
##        awk -vKEEP_WHITESPACE=1 -f dict.awk <dictionary.file> 
## NOTE: $INCLUDE directives are silently ignored
## 
BEGIN {
  print "/* This file is generated automatically."
  for (i = 1; i < ARGC; i++)
	 print " * Source file: " ARGV[i] 
  print " *"
  print " * Naming convention:"
  print " *     DA_XXX          -   Dictionary Attribute XXX"
  print " *     DV_XXX_YYY      -   Dictionary Value YYY corresponding to attribute XXX"	
  print " */"
  print "#ifndef _gnu_radius_dictionary_h"
  print "#define _gnu_radius_dictionary_h"		 
}

END {
	print "#endif /* !_gnu_radius_dictionary_h */"
}		

## Output the appropriate comment starter.
##
function comment_start() {
  if (comment_line == 1)
    return "/*"
  else
    return " *"
}

## Convert the dictionary name into a C identifier name
function cname(str) {
  gsub("-", "_", str)
  return toupper(str)  
}

## Process comments. 
/#VALUE/ { next }
/#ATTRIBUTE/ { next }
/#\$.*/ { next }
/^\$.*/ { next }
/##.*/ { next }
/#.*/ {
  comment_line++;
  printf "%s %s\n", comment_start(), substr($0,2)
  next  
}

## At the beginning of any non-comment line: check if we were in a comment
## and close it if so.
{ if (comment_line) 
    print " */"
  comment_line = 0; }

## empty line
NF==0 { if (KEEP_WHITESPACE) print "" }

## Attribute definition
$1 == "ATTRIBUTE" {
  name = cname($2);
  if (!defined[name]) {
    print "#define DA_" name " " $3
    defined[name]++
  }
}

## Value definition
$1 == "VALUE" {
  name = cname($2) "_" cname($3)
  if (!defined[name]) {  
    print "#define DV_" name " " $4
    defined[name]++
  }    
}
