divert(-1)dnl
dnl This file is part of GNU RADIUS.
dnl Copyright (C) 2001 Sergey Poznyakoff
dnl  
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl  
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl  
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software Foundation,
dnl Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
divert{}dnl
define({ARGS},ifdef({server}, -hserver) ifdef({port}, -P port)  ifdef({username},-u username) ifdef({password}, -p password))
define({CREATEDATABASE},
ifelse(MODE,{STRUCT},{
CREATE DATABASE $1;
USE $1;},
MODE,{CREATE},{
mysql ARGS < mysql.struct
}))

define({CREATETABLE},
ifelse(MODE,{STRUCT},{CREATE TABLE $1 ($2);}))

define({BYTE_T},{int(3)})dnl
define({SHORTINT_T},{int(5)})dnl
define({INT_T},{int(10)})dnl
define({LONGINT_T},{int(10)})dnl
define({CHAR_T},{char($1)})dnl
define({VARCHAR_T},{varchar($1)})dnl
define({CI},{binary})dnl
define({TIME_T},{datetime{}ifelse({$#}, {1},{ DEFAULT $1})})dnl

define({INDEX},{{INDEX} {$1} (shift($@))})
define({UNIQUE}, {{UNIQUE} {$1} (shift($@))})
define({COMMA},{,})

define({DB_PRIV},{
ifelse(MODE,{STRUCT},
{
USE mysql;
DELETE FROM user WHERE user='radius';
DELETE FROM db WHERE user='radius';
GRANT INSERT,UPDATE,DELETE,SELECT on RADIUS.calls to radius@"%";
GRANT SELECT on RADIUS.passwd to radius@'%';
GRANT SELECT on RADIUS.groups to radius@'%';
GRANT SELECT on RADIUS.attrib to radius@'%';
UPDATE user set password=password("DB_PWD") where user="radius";
FLUSH PRIVILEGES;
})})