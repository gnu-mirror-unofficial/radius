# Copyright (C) 2000,2001,2004 Sergey Poznyakoff
#
# This program generates the completion tables basing on the yacc's
# verbose output file (y.output). 
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# -----------------------------------------------------------------------
# usage: awk -f comptab.awk -vSKEL=skeleton -vKEYWORD=keywords y.output > \
#            comptab.c
#
# Variables SKEL and KEYWORD are assigned the names of skeleton and keyword
# file, correspondingly.
# Kyword file is a list of terminal symbols, one symbol per line. Each
# line should follow the format:
#    token  input  
# where:
#    token       is the token symbolic name as used in the input grammar
#    input       is the corresponding input sequence
#
# Skeleton file is the completion framework in C. 
#
# The program understands outputs from berkeley yacc and bison.

BEGIN {
	# Generate output header
	print "/* This file is generated automatically. Please do not edit. */"
	print "#line 1 \"" SKEL "\""
	SKEL_LINE = 0
	while ((getline <SKEL) > 0) {
		SKEL_LINE++
		if ($1 == "@@DATA@@") 
			break;
		print $0
	}
	# Read the keyword file
	kwcount = 0
	while (getline < KEYWORD) {
		if (NF == 2 && !match($0, "^#")) {
			kw[$1] = sprintf("\t\"%s\",%d,%s",$2,length($2),$1)
			kwnum[$1] = kwcount
			kwpos[kwcount++] = $1	
#			kwind[$1] = -1	
		} 
	}
	cur_state = -1
}

/^[sS]tate  *[0-9][0-9]*/ {
	cur_state = $2;
}

cur_state>=0 && /.* \. .*/ {
	for (i = 1; i <= NF; i++) {
		if ($i == ".") {
			num = i;
			break;
		}
	}
	state_lhs[cur_state] = $(i-1)
	lhs = $(i-1)
	rhs_cnt=0
	successor_rule=0
}
		
$2 == "shift" || $2 == "reduce" || $2 == "shift," {
	if (kw[$1] != "") {
		state_rhs[cur_state,rhs_cnt++] = $1
		if (cur_state==0)
	             kw_init[$1]=1;
		next
	} else if ($1 == "$default" && match($0, "reduce using rule [0-9]+ \\(.*\\)")) {
		match($0, "\\(.*\\)")
#		print cur_state " FOUND DEFAULT " substr($0,RSTART+1,RLENGTH-2)
		successor_rule = substr($0,RSTART+1,RLENGTH-2)
        }
	next
}

successor_rule == $1 && /go to state [0-9]+/ {
#	print "SSTATE " $5
	state_successor[cur_state] = $5
}	

function expand_successors(state,  i,j) {
	if (expand_stack[state])
		return;
	if (state_successor[state]) {
		expand_stack[state] = 1;
		expand_successors(state_successor[state])
		delete expand_stack[state]	
		for (j = 0; state_rhs[state,j]; j++)
			/* nothing */;
		for (i = 0; i < state_rhs[state_successor[state],i]; i++)
			state_rhs[state,j++] = state_rhs[state_successor[state],i]
	}			
}

function set_successor(kw,succ,   i) {
	for (i = 0; kw_sucessor[kw,i]; i++)
		if (kw_sucessor[kw,i] == succ)
			return;
	kw_sucessor[kw,i] = succ
}

END {
	for (i = 0; i <= cur_state; i++) {
		if (kw[state_lhs[i]] != "") {
			expand_successors(i)
			for (j = 0; state_rhs[i,j]; j++)
				set_successor(state_lhs[i],state_rhs[i,j])
		}
	}

	for (k in kw) {
		if (kw[k] != "") {
			print "static int kw_" k "_successors[] = {"
			for (i = 0; kw_sucessor[k,i]; i++)
				print "\t" kw_sucessor[k,i] ","
			print "\t0"
			print "};"
			print ""
	        } 		    
	}	

	print "static struct key_tab key_tab[] = {";
	for (k in kw) {
		if (kw[k] != "") 
			printf "\t%s,%d,kw_%s_successors,\n", kw[k], kw_init[k],k;
	}	       
	print "\tNULL"
	print "};"	
	
	# Generate output footer
	print "#line " SKEL_LINE+1 " \"" SKEL "\""
	while ((getline <SKEL) > 0) {
		print $0
	}		
}	



