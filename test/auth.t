#######
## auth.t
## $Id$
## This script is used to send the authentication request to the
## radius server
##
## usage: radtest username=LOGIN pwd=\"PASSWORD\" port=PORTNO auth.t
##
## where LOGIN is the loginname and
##       PASSWORD is the password for this login,
##       PORTNO is the NAS port number

auth_packet = { User-Name = $username, Password = $pwd,
		NAS-Port-Id = $port,
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.1 };

send auth 1 $auth_packet;
expect 2 "Returned " $REPLY_CODE ", Reply-Message = " $REPLY[Reply-Message] ;

