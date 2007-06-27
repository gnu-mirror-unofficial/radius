divert(-1)
dnl This file is part of GNU Radius.
dnl Copyright (C) 2001,2003,2007 Free Software Foundation, Inc.
dnl
dnl Written by Sergey Poznyakoff
dnl  
dnl GNU Radius is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl  
dnl GNU Radius is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl  
dnl You should have received a copy of the GNU General Public License
dnl along with GNU Radius; if not, write to the Free Software Foundation,
dnl Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
define({ARGS},ifdef({server}, -h server) ifdef({port}, -P port)  ifdef({CREATOR},-u CREATOR) ifdef({CREATOR_PASSWORD}, -p{}CREATOR_PASSWORD))
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
define({ENUM_T},{enum (shift($@))})

define({INDEX},{{INDEX} {$1} (shift($@))})
define({UNIQUE}, {{UNIQUE} {$1} (shift($@))})
define({COMMA},{,})

define({DB_PRIV},{
ifelse(MODE,{STRUCT},
{
USE mysql;
DELETE FROM user WHERE user='DB_USER';
DELETE FROM db WHERE user='DB_USER';
GRANT INSERT,UPDATE,DELETE,SELECT on RADIUS.calls to DB_USER@'%';
GRANT SELECT on RADIUS.passwd to DB_USER@'%';
GRANT SELECT on RADIUS.groups to DB_USER@'%';
GRANT SELECT on RADIUS.attrib to DB_USER@'%';
GRANT SELECT on RADIUS.naspools to DB_USER@'%';
GRANT SELECT,UPDATE on RADIUS.ippool to DB_USER@'%';
UPDATE user set password=password('DB_PWD') where user='DB_USER';
FLUSH PRIVILEGES;
})})
divert{}dnl
