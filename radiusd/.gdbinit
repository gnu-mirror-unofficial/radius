# This file is part of GNU Radius.
# Copyright (C) 2001,2003 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# GNU Radius is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

## Some initial setup first:
# Force loading of symbols
set main

# Find radlib sources
dir ../lib

handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIGPIPE nostop print pass
handle SIGHUP  nostop noprint pass
handle SIGCHLD nostop print pass

# Make sure radiusd won't spawn any children 
break main
commands
 set variable debug_flag=1
 set variable foreground=1
 set variable spawn_flag=0
 continue
end

# Do not allow abort and exit run without our knowing it
break abort
break exit

## Define some handy macros

# Print type of the attribute/value pair
define _pt
if $arg0->type == 0
	echo STRING
else
 if $arg0->type == 1
	echo INTEGER
 else
  if $arg0->type == 2
	echo IPADDR
  else
   if $arg0->type == 3
	echo DATE
   else
	output $arg0->type
   end
  end
 end
end
end

define pt
_pt $arg0
echo \n
end
document pt
Print type of the A/V pair $
end

# Print the value of an A/V pair
define _pv
output (($arg0->type == 0 || $arg0->type == 3) ? $arg0->v.string.s_value : (($arg0->type == 1) ? $arg0->v.ival : grad_ip_iptostr($arg0->v.ival, (char*)0)))
end

define pv
_pv $arg0
echo \n
end
document pv
Print the value of the A/V pair $arg0
end

define _po
 if $arg0->operator == grad_operator_equal
	echo =
 else
  if $arg0->operator == grad_operator_not_equal
	echo !=
  else
   if $arg0->operator == grad_operator_less_than
	echo <
   else
    if $arg0->operator == grad_operator_greater_than
	echo >
    else
     if $arg0->operator == grad_operator_less_equal
	echo <=
     else
      if $arg0->operator == grad_operator_greater_equal
	echo >=
      else
	output $arg0->operator
      end
     end
    end
   end
  end
 end
end

define po
_po $arg0
echo \n
end
document po
Print the operator of the pair $arg0
end

define _pp
output /x $arg0
printf " ("
_pt $arg0
printf ") %s ", $arg0->name
_po $arg0
printf " "
_pv $arg0
end

define pp
_pp $arg0
echo \n
end

define plist
 set $last=$arg0
 while $last
  _pp $last
  echo ,\n
  set $last=$last->next
 end
end
document plist
Print A/V pair list
end

define print_authcode
 output auth_code_str($arg0->code)
end
document print_authcode
Print the code value of grad_request_t $arg0
end

define preq
 print_authcode $arg0
 printf " {\n"
 plist $arg0->request
 printf "}\n"
end
document preq
Print grad_request_t structure $arg0
end


 
