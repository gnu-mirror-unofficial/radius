# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


# Translate old-style auth level into new print- statement
function authlevel(s) {
	if (s == "auth")
		return "print-auth"
	else if (s == "pass")
		return "print-pass"
	else if (s == "failed_pass")
		return "print-failed-pass"
	else
		return "# " s;
}

function chanoption(s) {
	if (s == "pid")
		return "print-pid"
	else if (s == "level")
		return "print-priority"
        else if (s == "cons")
                return "print-cons"
	else
		return "# " s;
}

## State map:
##     0   --  initial
##     1   --  'logging' block
##     2   --  'category auth' block
##     3   --  'channel' block
##     4   --  'cntl' block

# skip comments
/ *#/ {print; next}
/ *\/\// {print; next}

$1 == "logging" { state = 1 }

state == 1 && $1 == "category" && $2 == "auth" { state = 2 }
state == 2 && $1 == "level" {
	gsub("\t", "        ");
	indent_level = match($0, "level");
	for (i = 2; i <= NF; i++) {
		gsub(";", "", $i)
		n = split($i, la, ",")
		for (j = 1; j <= n; j++) 
			printf("%*.*s%s yes;\n",
			       indent_level, indent_level, "",
			       authlevel(la[j]))
	}
	next;
}	

state == 1 && $1 == "channel" { state = 3 }

state == 3 && $1 == "option" {
	gsub("\t", "        ");
	indent_level = match($0, "option");
	for (i = 2; i <= NF; i++) {
		gsub(";", "", $i)
		n = split($i, la, ",")
		for (j = 1; j <= n; j++)
			printf("%*.*s%s yes;\n",
			       indent_level, indent_level, "",
			       chanoption(la[j]))
	}
	next
}		

state == 0 && $1 == "cntl" { state = 4; }

/.*{.*/ { nesting_level++; }
/.*}.*/ {
	prev_state = state;
	nesting_level--;
	if (nesting_level == 0) {
		state = 0;
		if (prev_state == 4)
			next;
	} else if (nesting_level == 1) {
		if (state == 2 || state == 3)
			state = 1;
	}
}

state != 4 { print }
	
