#######
## acct.on.t
## $Id$
## This script sends the Accounting-On record
##
## usage: radtest acct.on.t

send acct 4 { Acct-Status-Type = Accounting-On,
              NAS-Identifier = "localhost",
              NAS-IP-Address = 127.0.0.1 }; 
expect 5;

