divert(-1)
dnl This file is part of GNU Radius.
dnl Copyright (C) 2001,2003,2004,2007 Free Software Foundation, Inc.
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
changequote({,})
include(config.m4)
include(INCLUDE)
ifdef({DB_USER},,{define(DB_USER,{radius})})
ifdef({DB_PWD},,{define({DB_PWD},{guessme})})
divert{}dnl

CREATEDATABASE(RADIUS)

define({USER_COLUMN},
       {user_name           VARCHAR_T(32) CI default '' not null})

CREATETABLE(passwd, {
  USER_COLUMN,
  service             CHAR_T(16) default 'Framed-PPP' not null,
  password            CHAR_T(64),
  active              ENUM_T(1,'Y','N') default 'Y' not null COMMA
  INDEX(uname, user_name,active) COMMA
  UNIQUE(usrv, user_name,service,active) 
})
CREATETABLE(groups, {
  USER_COLUMN,
  user_group          CHAR_T(32) COMMA
  INDEX(grp, user_name)
})
CREATETABLE(authfail, {
  USER_COLUMN,
  count               SHORTINT_T,
  time                TIME_T('1970-01-01 00:00:00') NOT NULL COMMA
  UNIQUE(uname, user_name)
})  
CREATETABLE(attrib, {
  USER_COLUMN,
  attr                CHAR_T(32) default '' not null,
  value               CHAR_T(128),
  op                  ENUM_T(2,'=','!=','<','>','<=','>=') default NULL COMMA
  INDEX(uattr,user_name,attr,op)
})
CREATETABLE(calls, {
  status              SHORTINT_T not null,
  USER_COLUMN,
  realm_name          VARCHAR_T(32) CI default '' not null,
  event_date_time     TIME_T('1970-01-01 00:00:00') NOT NULL,
  nas_ip_address      CHAR_T(17) default '0.0.0.0' not null,
  nas_port_id         INT_T,
  acct_session_id     CHAR_T(17) DEFAULT '' NOT NULL,
  acct_session_time   LONGINT_T,
  acct_input_octets   LONGINT_T,
  acct_output_octets  LONGINT_T,
  connect_term_reason INT_T,
  framed_ip_address   CHAR_T(17),
  called_station_id   CHAR_T(32),
  calling_station_id  CHAR_T(32) COMMA
  INDEX(name_sid, user_name,acct_session_id) COMMA
  INDEX(name_stat_sid,user_name,status,acct_session_id) COMMA
  INDEX(stat_nas,status,nas_ip_address) COMMA
  INDEX(realm,realm_name)
})

CREATETABLE(naspools, {
  nas CHAR_T(17) default '0.0.0.0' not null,
  pool CHAR_T(8),
  PRIMARY KEY (nas)
})

CREATETABLE(ippool, {
  pool CHAR_T(8) default 'DEFAULT' NOT NULL,
  ipaddr CHAR_T(17) default '' not null,
  status ENUM_T(4,'FREE','BLCK','FIXD','ASGN','RSRV') default 'FREE' not null,
  time TIME_T('1970-01-01 00:00:00') NOT NULL,
  USER_COLUMN COMMA
  INDEX(ippool_name,user_name) COMMA
  INDEX(ippool_ipaddr,ipaddr)
})

DB_PRIV
