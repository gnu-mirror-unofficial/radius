#######
## This script tests rewriting of cisco AS5300 Session Ids
##

username="aud";
pwd = "Oystein";


auth_packet = { User-Name = $username, Password = $pwd,
		Acct-Session-Id = "120104/18:02:06.020 EEST Thu Dec 7 2000/odessa-voip-1.farlep.voip/1B22539E 86E6603F 0 19C974C0/answer/Telephony////",
		Cisco-PRI-Circuit = "ISDN 2:D:11",
		Acct-Status-Type = Start,
		NAS-Identifier = "localhost",
		NAS-IP-Address = 127.0.0.1 };

send acct 4 $auth_packet;
expect 5 "Returned " $REPLY_CODE ;

