divert(-1)dnl
dnl This file is part of GNU Radius.
dnl Copyright (C) 2001, 2003, 2007, 2010, 2013 Free Software Foundation, Inc.
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
dnl along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>.
define({ARGS},{ifdef({server}, -h{}server){}ifdef({port}, -p{}port){}dnl
ifdef({CREATOR},{ -U CREATOR}){}ifdef({CREATOR_PASSWORD},{ -W})})

define({CREATEDATABASE},ifelse(MODE,{CREATE}, {
createdb ARGS {$1}
psql ARGS -d $1 < pgsql.struct
}))

define({CREATETABLE},{ifelse(MODE,{STRUCT},{
divert
define({TABLENAME},{$1})
CREATE TABLE $1 ($2);
undivert(1)})})

define({BYTE_T},{int2})dnl
define({SHORTINT_T},{int2})dnl
define({INT_T},{int8})dnl
define({LONGINT_T},{int8})dnl
define({CHAR_T},{character($1)})dnl
define({VARCHAR_T},{character($1)})dnl
define({CI})dnl
define({TIME_T},{timestamp}{}ifelse({$#}, {1},{ DEFAULT $1}))dnl
define({ENUM_T},{ifelse({$1},1,char,character({$1}))})

define({INDEX},{divert(1)
CREATE {INDEX} $1 on TABLENAME (shift($@));
divert})
define({UNIQUE},{divert(1)
CREATE {UNIQUE INDEX} $1 on TABLENAME (shift($@));
divert})
define({COMMA})

define({DB_PRIV},{
ifelse(MODE,{STRUCT},
{
CREATE USER "DB_USER" WITH PASSWORD 'DB_PWD';
REVOKE ALL on "calls" from PUBLIC;
GRANT INSERT,UPDATE,DELETE,SELECT on "calls" to "DB_USER";
REVOKE ALL on "passwd" from PUBLIC;
GRANT SELECT on "passwd" to "DB_USER";
REVOKE ALL on "groups" from PUBLIC;
GRANT SELECT on "groups" to "DB_USER";
REVOKE ALL on "attrib" from PUBLIC;
GRANT SELECT on "attrib" to "DB_USER";
REVOKE ALL on "naspools" from PUBLIC;
GRANT SELECT on "naspools" to "DB_USER";
REVOKE ALL on "ippool" from PUBLIC;
GRANT SELECT,UPDATE on "ippool" to "DB_USER";
})})
divert{}dnl
