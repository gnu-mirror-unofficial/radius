#######
## Test for handling MAX NAS-Port-Id attribute
##

username="aud";
pwd = "Oystein";


auth_packet = { User-Name = $username, Password = $pwd,
		NAS-Port-Id = 20207,
		Acct-Status-Type = Start,
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.2 };

send acct 4 $auth_packet;
expect 5 "Returned " $REPLY_CODE ;

