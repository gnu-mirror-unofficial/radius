#######
## A test for AS5300 packet rewriting
##

username="aud";
pwd = "Oystein";


auth_packet = { User-Name = $username, Password = $pwd,
		Cisco-PRI-Circuit = "ISDN 2:D:11",
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.1 };

send auth 1 $auth_packet;
expect 2 "Returned " $REPLY_CODE ", Reply-Message = " $REPLY[Reply-Message] ;

