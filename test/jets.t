#######
## jets.t
## This script tests the jetstream_fixup function in raddb/rewrite
##

username = "a_very_lon/g_login";
pwd ="";
port=10;

auth_packet = { User-Name = $username, Password = $pwd,
		NAS-Port-Id = $port,
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.1 };

send auth 1 $auth_packet;
expect 2 "Returned " $REPLY_CODE ", Reply-Message = " $REPLY[Reply-Message] ;

