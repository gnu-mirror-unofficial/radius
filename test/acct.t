#######
## acct.t
## $Id$
## This script is used to send an accounting record to a radius server
##
## usage: radtest username=LOGIN port=PORT session=SESSID type=TYPE \
##        acct.t
##
## where LOGIN is the login name
##       PORT  is the port number
##       SESSID is the session ID
##       TYPE is any valid Acct-Status-Type value.

acct_packet = { User-Name = $username,
		Acct-Status-Type = $type,
		Acct-Session-Id = $session,
		NAS-Port-Id = $port,
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.1 };
send acct 4 $acct_packet;
expect 5;

