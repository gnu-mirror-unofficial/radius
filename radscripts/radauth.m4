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
LOGIN=${1:?}
PWD=${2:&Password: }

if ${NASIP:-} = ""
	NASIP=$SOURCEIP

LIST = ( User-Name = $LOGIN User-Password = $PWD NAS-IP-Address = $NASIP )
if ${pid:-} != ""
	LIST = $LIST + (NAS-Port-Id = $pid)

send auth Access-Request $LIST

while 1
begin
  if $REPLY_CODE = Access-Accept
  begin
     print "Authentication passed. " + $REPLY[[Reply-Message*]] + "\n"
     if ${ACCT:-no} = no
	exit 0
     if ${SID:-} = ""
     	input "Enter session ID " SID
     send auth Accounting-Request $LIST + \
               ( Acct-Status-Type = Start Acct-Session-Id = $SID )
     if $REPLY_CODE != Accounting-Response
     begin
        print "Accounting failed.\n"
        break
     end
     print "Accounting OK.\n"
     exit 0
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

# End of radauth
