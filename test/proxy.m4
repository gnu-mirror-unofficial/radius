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

TOOLDIR(radiusd.proxy)
BEGIN(--proxy)

SEQUENCE(Auth,
Checking Basic Authentication Types,
TEST(send auth 1 User-Name = "accept@remote", expect 2) 
TEST(send auth 1 User-Name = "reject@remote", expect 3) 
TEST(send auth 1 User-Name = "local@remote" Password = "guessme",
     expect 2)
TEST(send auth 1 User-Name = "local@remote" Password = "bad",
     expect 3)
TEST(send auth 1 User-Name = "crypt@remote" Password = "hamlet",
     expect 2)) 

SEQUENCE(Nest,
Checking Nested realms,
TEST(send auth 1 User-Name = "accept@local@remote", expect 2))

SEQUENCE(Acct-Start,
Checking accountng stop,
TEST(send acct 4 User-Name = "simuse@remote" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 1 \
                    Acct-Session-Id = "0001" \
                    Acct-Status-Type = Start, 
     expect 5))

SEQUENCE(Acct-Stop,
Checking accountng stop,
TEST(send acct 4 User-Name = "simuse@remote" \
                    NAS-IP-Address = "127.0.0.1" \
                    NAS-Port-Id = 1 \
                    Acct-Session-Id = "0001" \
                    Acct-Status-Type = Stop, 
     expect 5))

END
