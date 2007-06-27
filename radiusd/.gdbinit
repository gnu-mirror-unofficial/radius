## This file is part of GNU Radius.
## Copyright (C) 2000,2001,2002,2003,2004,2007 Free Software Foundation
##
## Written by Sergey Poznyakoff
##
## GNU Radius is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## GNU Radius is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with GNU Radius; if not, write to the Free Software Foundation,
## Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 

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
Print type of the A/V pair $arg0
end

define print_iptostr
printf "%d.%d.%d.%d", ($arg0 >> 24)&0xff, ($arg0 >> 16)&0xff, ($arg0>>8)&0xff, $arg0 &0xff  
end
document print_iptostr
Print argument (IPv4 address in host order) in a conventional form
end

# Print the value of an A/V pair
define _pv
if $arg0->type == 0 || $arg0->type == 3
 output $arg0->v.string.s_value
else
 if $arg0->type == 1
  output $arg0->v.ival
 else
  print_iptostr $arg0->v.ival  
 end
end
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

define print_reqcode
## Warning: do not edit this mess manually, use (grad-request-region-to-gdb)
## from scripts/radius-devel.el
if $arg0->code == 1
 echo Access-Request
else
 if $arg0->code == 2
  echo Access-Accept
 else
  if $arg0->code == 3
   echo Access-Reject
  else
   if $arg0->code == 4
    echo Accounting-Request
   else
    if $arg0->code == 5
     echo Accounting-Response
    else
     if $arg0->code == 6
      echo Accounting-Status
     else
      if $arg0->code == 7
       echo Password-Request
      else
       if $arg0->code == 8
        echo Password-Ack
       else
        if $arg0->code == 9
         echo Password-Reject
        else
         if $arg0->code == 10
          echo Accounting-Message
         else
          if $arg0->code == 11
           echo Access-Challenge
          else
           if $arg0->code == 12
            echo Status-Server
           else
            if $arg0->code == 13
             echo Status-Client
            else
             if $arg0->code == 31
              echo Ascend-Terminate-Session
             else
              if $arg0->code == 33
               echo Ascend-Event-Request
              else
               if $arg0->code == 34
                echo Ascend-Event-Response
               else
                if $arg0->code == 51
                 echo Ascend-Allocate-IP
                else
                 if $arg0->code == 52
                  echo Ascend-Release-IP
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
        end
       end
      end
     end
    end
   end
  end
 end
end
end
document print_reqcode
Print the code value of grad_request_t $arg0
end

define preq
 printf "From "  
 print_iptostr $arg0->ipaddr
 printf "\n" 
 print_reqcode $arg0
 printf " {\n"
 plist $arg0->avlist
 printf "}\n"
end
document preq
Print grad_request_t structure $arg0
end

# End of .gdbinit
 
