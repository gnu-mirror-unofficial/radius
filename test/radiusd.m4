# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001 Sergey Poznyakoff
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# $Id$

TOOLDIR(radiusd)
BEGIN

SEQUENCE(Auth,
Checking Basic Authentication Types,
TEST(send auth 1 User-Name = "accept", expect 2)
TEST(send auth 1 User-Name = "reject", expect 3)
TEST(send auth 1 User-Name = "local" Password = "guessme", expect 2)
TEST(send auth 1 User-Name = "local" Password = "bad", expect 3)
TEST(send auth 1 User-Name = "crypt" Password = "hamlet", expect 2))

SEQUENCE(Reply,
Checking Reply Attributes,
TEST(send auth 1 User-Name = "reply" Password = "guessme",
     expect 2 Service-Type = 2 Framed-Protocol = 1)
TEST(send auth 1 User-Name = "framed-ip" NAS-Port-Id = 10,
     expect 2 Service-Type = 2 Framed-Protocol = 1 Framed-IP-Address = "127.0.0.11"))

SEQUENCE(Begin,
[Checking BEGIN Keyword],
TEST(send auth 1 User-Name = "accept" NAS-IP-Address = "127.0.0.2" NAS-Port-Id = 2,
     expect 2 Framed-IP-Address = "127.10.0.3")) 

SEQUENCE(Default,
Checking DEFAULT Keyword,
TEST(send auth 1 User-Name = "no-such-user" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 2,
    expect 3)
TEST(send auth 1 User-Name = "no-such-user" \
                    NAS-IP-Address = "127.0.0.3" \
                    NAS-Port-Id = 2, 
    expect 2 Reply-Message = "OK. Come in.")
TEST(send auth 1 User-Name = "no-such-user" \
                    NAS-IP-Address = "127.0.0.4" \
                    NAS-Port-Id = 2,
    expect 3 Reply-Message = "Wrong NAS"))

SEQUENCE(Match,
Checking Match-Profile,
TEST(send auth 1 User-Name = "match1" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 1 \
                    NAS-Identifier = "een",
    expect 2 Service-Type = Framed-User \
               Framed-Protocol = PPP \
               Framed-IP-Address = "127.10.10.1" )
TEST(send auth 1 User-Name = "match1" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 1 \
                    NAS-Identifier = "to",
    expect 2 Service-Type = Framed-User \
               Framed-Protocol = PPP \
               Framed-IP-Address = "127.10.10.2")
TEST(send auth 1 User-Name = "match1" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 2 \
                    NAS-Identifier = "een",
     expect 3)
TEST(send auth 1 User-Name = "match1" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Identifier = "een",
     expect 3))

SEQUENCE(Hints,
Checking hints,
TEST(send auth 1 User-Name = "hint.1",
     expect 2 Reply-Message = "Hint 1")
TEST(send auth 1 User-Name = "hint.2",
     expect 2 Reply-Message = "Hint 2")
TEST(send auth 1 User-Name = "hint",
     expect 3 Reply-Message = No suffix))

SEQUENCE(Huntgroups,
Checking huntgroups,
TEST(send auth 1 User-Name = "accept" \
             NAS-IP-Address = 127.0.0.4 \
	     NAS-Port-Id = 2,
     expect 2)
TEST(send auth 1 User-Name = "accept" \
             NAS-IP-Address = 127.0.0.4 \
	     NAS-Port-Id = 5,
        expect 3))

IFSEQUENCE(Scheme-Auth, USE_SERVER_GUILE,
Checking Scheme Authentication,
TEST(send auth 1 User-Name = "scheme" \
	             NAS-IP-Address = "127.0.0.1",
	 expect 2 Framed-MTU = 8096) 
TEST(send auth 1 User-Name = "scheme" \
	                NAS-IP-Address = "127.0.0.2",
         expect 2 Framed-MTU = 256))

SEQUENCE(Access,
Checking Access lists,
[TEST(send auth 1 User-Name = "bad-one",
 [expect 3 Reply-Message = "Sorry, your account is currently closed\\r\\n"])])

IFSEQUENCE(Menu, USE_LIVINGSTON_MENUS,
Checking Menus,
[TEST(send auth 1 User-Name = "menu",
     [print \$REPLY[\[Reply-Message*\]]],
     [*** This is a test Menu coming from RADIUS ***\r\r\n\r\r\nMenus can contain up to 1500 bytes of data.  They can contain\r\r\nany non-null characters.  Option selections require an exact match.\r\r\nIf case insensitivity is required, enter the menu choices twice,\r\r\nonce in upper and once in lower case.\r\r\n\r\r\nPlease enter an option:\r\r\n\r\r\n1 Start PPP session\r\r\n2 Start CSLIP session\r\r\n3 Start SLIP session\r\r\n4 Start login session\r\r\n5 Go to second menu\r\r\n6 Exit\r\r\n\r\r\nOption: ])
TEST(send auth 1 User-Name = "menu" \
                     Password = "5" State = "MENU=menu1",
     [print \$REPLY[\[Reply-Message*\]]],
     [*** This is a test Menu coming from RADIUS ***\r\r\n\r\r\nMenus can call other menus.\r\r\nThis menu is called when option 5 of menu1 is selected.\r\r\nMenu choices can be words as well as numbers.\r\r\n\r\r\nPlease enter an option:\r\r\n\r\r\nra       Connect to host ra\r\r\nsol      Connect to host sol\r\r\nweevil   Connect to host weevil\r\r\ntop      Return to top level menu\r\r\nquit     Quit\r\r\n\r\r\nOption: ]) 
TEST(send auth 1 User-Name = "menu" \
                     Password = "sol" \
                     State = "MENU=menu2",
        expect 2 Service-Type = 1 \
                  Login-IP-Host = "127.0.0.1" \
                  State = "MENU=\menu2" \
                  Termination-Action = 1)]) 

SEQUENCE(Acct-start,
Checking accountng start,
TEST(send acct 4 User-Name = "simuse" \
                  NAS-IP-Address = "127.0.0.1" \
                  NAS-Port-Id = 1 \
                  Acct-Session-Id = "0001" \
                  Acct-Status-Type = Start,
      expect 5)
DISPLAY(Checking Simultaneous-Use attribute)
TEST(send auth 1 User-Name = "simuse",
     expect 3 Reply-Message = "\\r\\nYou are already logged in - access denied\\r\\n"))


SEQUENCE(Acct-Stop,
Checking accountng stop,
TEST(send acct 4 User-Name = "simuse" \
                  NAS-IP-Address = "127.0.0.1" \
                  NAS-Port-Id = 1 \
                  Acct-Session-Id = "0001" \
                  Acct-Status-Type = Stop,
      expect 5)
DISPLAY(Checking Simultaneous-Use attribute)
TEST(send auth 1 User-Name = "simuse",
	    expect 2 Service-Type = 2))

SEQUENCE(Rewrite,
Checking rewrite rules,
[
TEST(send auth 1 User-Name = rewrite_max \
	          NAS-IP-Address = 127.0.0.5 \
	          NAS-Port-Id = 20212,
     expect 2 Reply-Message = OK)
TEST(send auth 1 User-Name = "WGROUP\\\\rewrite_nt" \
	          NAS-IP-Address = 127.0.0.5 \
	          NAS-Port-Id = 2,
     expect 2 Reply-Message = OK)
TEST(send auth 1 User-Name = "rewrite_je/tstream" \
	            NAS-IP-Address = 127.0.0.5 \
		    NAS-Port-Id = 3,
            expect 2 Reply-Message = OK)		   
TEST(send auth 1 User-Name = "rewrite_cisco" \
	          NAS-IP-Address = 127.0.0.5 \
	          Cisco-PRI-Circuit = "ISDN 2:D:123" \
Acct-Session-Id = "120104/18:02:06.020 EEST Thu Dec 7 2000/hostname/1B22539E 86E6603F 0 19C974C0/answer/Telephony////",
     expect 2 Reply-Message = OK)])

SEQUENCE(Exec-Program-Wait,
Checking Exec-Program-Wait attribute,
[
TEST(send auth 1 User-Name = "execwait" NAS-Port-Id = 0,
     [expect 2 Service-Type = 1 Reply-Message = "Welcome, execwait"])
TEST(send auth 1 User-Name = "execwait" NAS-Port-Id = 1, 
     expect 3)])

IFSEQUENCE(Scheme-Acct, USE_SERVER_GUILE,
Checking Scheme Accounting,
TEST(send acct 4 User-Name = "scheme" \
	                NAS-IP-Address = "127.0.0.1" \
                        NAS-Port-Id = 1 \
                        Acct-Status-Type = Start \
			Acct-Session-Id = "0001",
	        expect 5)
# Fixme: check file
)

END
