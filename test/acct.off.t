#######
## acct.off.t
## $Id$
## This script sends the Accounting-Off record
##
## usage: radtest acct.off.t

send acct 4 { Acct-Status-Type = Accounting-Off,
	      NAS-Identifier = "localhost",
              NAS-IP-Address = 127.0.0.1 }; 
expect 5;

