include(SRCDIR/radscripts.m4)dnl
#! BINDIR/radtest -f
# This file is part of GNU Radius.
# Copyright (C) 2004 Free Software Foundation, Inc.
#
# Written by Sergey Poznyakoff
# 
# GNU Radius is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GNU Radius is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radius; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  

while getopt "An:s:P:hv"
begin
  case $OPTVAR in
  "-n")	NASIP = $OPTARG 
  "-s")	SID = $OPTARG 
  "-P") pid = $OPTARG 
  "-v")	set -v 
  "-A")	ACCT = yes 
  "-h") begin
          print <<-EOT
		usage: radauth [[OPTIONS]] login [[password]]
		Options are:
		  -A            Run accounting after successful authentication
		  -n IP		Set NAS IP address
		  -s SID	Set session ID
		  -P PORT	Set NAS port number
		EOT
          exit 0
        end
  ".*")	begin
          print "Unknown option: " $1
	  exit 1
        end
  end
end

[shift] ${OPTIND}-1

if $# > 4
begin
	print "Wrong number of arguments."
	print "Try radauth -h for more info"
	exit 1
end

case $1 in
"auth|acct|start|stop") begin
                          COMMAND=$1
                          [shift] 1
                        end
".*")	COMMAND="auth"
end

LOGIN=${1:?User name is not specified. Try radauth -h for more info.}

if ${NASIP:-} = ""
	NASIP=$SOURCEIP

LIST = ( User-Name = $LOGIN NAS-IP-Address = $NASIP )

accounting
begin
  if ${SID:-} = ""
    input "Enter session ID: " SID
  if ${pid:-} = ""
    input "Enter NAS port ID: " pid
  send auth Accounting-Request $1 + (Acct-Session-Id = $SID NAS-Port-Id = $pid)
  if $REPLY_CODE != Accounting-Response
  begin
    print "Accounting failed.\n"
    exit 1	
  end
  print "Accounting OK.\n"
  exit 0
end

authenticate
begin
  send auth Access-Request $1 + (User-Password = $2)
  while 1
  begin
    if $REPLY_CODE = Access-Accept
    begin
      print "Authentication passed. " + $REPLY[[Reply-Message*]] + "\n"
      if ${3:-no} = no
	exit 0
      accounting($1 + ( Acct-Status-Type = Start ))
    end else if $REPLY_CODE = Access-Reject
    begin
      print "Authentication failed. " + $REPLY[[Reply-Message*]] + "\n"
      break
    end else if $REPLY_CODE = Access-Challenge
    begin
      print $REPLY[[Reply-Message*]]
      input 
      send auth Access-Request \
           (User-Name = $LOGIN User-Password = $INPUT State = $REPLY[[State]])
      end else begin
        print "Authentication failed. Reply code " + $REPLY_CODE + "\n"
        break
      end
  end
  exit 1
end

case ${COMMAND} in
"auth")		authenticate($LIST, ${2:&Password: }, no)
"acct")         authenticate($LIST, ${2:&Password: }, yes)
"start")	accounting($LIST+(Acct-Status-Type = Start))
"stop")         accounting($LIST+(Acct-Status-Type = Stop))
".*")		begin
		  print "Unknown command. Try radauth -h for more info"
		  exit 1
	        end
end

# End of radauth
