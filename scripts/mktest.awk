BEGIN { INCR = 1; num = 0 }
/#.*/ { next }
/+/ { INCR = $2; next }
{ printf("ln -s %s.in %03d%s.exp\n", $1, num, $1); num += INCR }

	

