## Some initial setup first:
# Force loading of symbols
set main

# Find radlib sources
dir ../radlib

# Make sure radiusd won't spawn any children 
break main
commands
 set variable debug_flag=1
 set variable spawn_flag=0
 set variable foreground=1
 continue
end

# Do not allow abort and exit run without our knowing it
break abort
break exit
break sig_fatal

## Define some handy macros

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
Print type of the pair $
end

define _pv
output (($arg0->type == 0 || $arg0->type == 3) ? $arg0->v.string.s_value : (($arg0->type == 1) ? $arg0->v.ival : ip_hostname($arg0->v.ival)))
end

define pv
_pv $arg0
echo \n
end
document pv
Print the value of the A/V pair $arg0
end

define _po
 if $arg0->operator == PW_OPERATOR_EQUAL
	echo =
 else
  if $arg0->operator == PW_OPERATOR_NOT_EQUAL
	echo !=
  else
   if $arg0->operator == PW_OPERATOR_LESS_THAN
	echo <
   else
    if $arg0->operator == PW_OPERATOR_GREATER_THAN
	echo >
    else
     if $arg0->operator == PW_OPERATOR_LESS_EQUAL
	echo <=
     else
      if $arg0->operator == PW_OPERATOR_GREATER_EQUAL
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
 if $arg0->code == 1
	echo Auth-Request
 else
  if $arg0->code == 2
	echo Auth-Ack
  else
   if $arg0->code == 3
	echo Auth-Reject
   else
    if $arg0->code == 4
	echo Acct-Request
    else
     if $arg0->code == 5
	echo Acct-Reply
     else
      if $arg0->code == 6
	echo Acct-Status
      else
       if $arg0->code == 7
	echo Pwd-Request
       else
        if $arg0->code == 8
		echo Pwd-Ack
	else
		output $arg0->code
        end
       end
      end
     end
    end
   end
  end
 end
end
document print_authcode
Print the code value of AUTH_REQ $arg0
end

define pauth
 print_authcode $arg0
 printf " {\n"
 plist $arg0->request
 printf "}\n"
end
document pauth
Print AUTH_REQ structure $arg0
end


 