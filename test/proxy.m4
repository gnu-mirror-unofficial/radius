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
Checking Proxy Basic Authentication Types,
TEST(send auth 1 User-Name = QUOTE(accept@remote), expect 2) 
TEST(send auth 1 User-Name = QUOTE(reject@remote), expect 3) 
TEST(send auth 1 User-Name = QUOTE(local@remote) Password = QUOTE(guessme),
     expect 2)
TEST(send auth 1 User-Name = QUOTE(local@remote) Password = QUOTE(bad),
     expect 3)
TEST(send auth 1 User-Name = QUOTE(crypt@remote) Password = QUOTE(hamlet),
     expect 2)) 

SEQUENCE(Nest,
Checking Nested Realms,
TEST(send auth 1 User-Name = QUOTE(accept@local@remote), expect 2))

SEQUENCE(Acct-Start,
Checking Proxy Accountng Start,
TEST(send acct 4 User-Name = QUOTE(simuse@remote) \
                    NAS-IP-Address = 127.0.0.1 \
                    NAS-Port-Id = 1 \
                    Acct-Session-Id = QUOTE(0001) \
                    Acct-Status-Type = Start, 
     expect 5))

SEQUENCE(Acct-Stop,
Checking Proxy Accountng Stop,
TEST(send acct 4 User-Name = QUOTE(simuse@remote) \
                    NAS-IP-Address = 127.0.0.1 \
                    NAS-Port-Id = 1 \
                    Acct-Session-Id = QUOTE(0001) \
                    Acct-Status-Type = Stop, 
     expect 5))

END
