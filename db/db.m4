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
changequote({,})
include(config.m4)
include(INCLUDE)
ifdef({DB_USER},,{define(DB_USER,{radius})})
ifdef({DB_PWD},,{define({DB_PWD},{guessme})})
divert{}dnl
CREATEDATABASE(RADIUS)

CREATETABLE(passwd, {
  user_name           VARCHAR_T(32) CI default '' not null,
  service             CHAR_T(16) default 'Framed-PPP' not null,
  password            CHAR_T(64) COMMA
  INDEX(uname, user_name) COMMA
  UNIQUE(usrv, user_name,service) 
})
CREATETABLE(groups, {
  user_name           CHAR_T(32) CI default '' not null,
  user_group          CHAR_T(32) COMMA
  INDEX(grp, user_name)
})
CREATETABLE(attrib, {
  user_name           VARCHAR_T(32) CI default '' not null,
  attr                CHAR_T(32) default '' not null,
  value               CHAR_T(128),
  op                  enum('=','!=','<','>','<=','>=') default NULL COMMA
  INDEX(uattr,user_name,attr,op)
})
CREATETABLE(calls, {
  status              SHORTINT_T not null,
  user_name           VARCHAR_T(32) CI default '' not null,
  event_date_time     TIME_T('0000-00-00 00:00:00') NOT NULL,
  nas_ip_address      CHAR_T(17) default '0.0.0.0' not null,
  nas_port_id         INT_T,
  acct_session_id     CHAR_T(16) DEFAULT '' NOT NULL,
  acct_session_time   LONGINT_T,
  acct_input_octets   LONGINT_T,
  acct_output_octets  LONGINT_T,
  connect_term_reason INT_T,
  framed_ip_address   CHAR_T(17),
  called_station_id   CHAR_T(32),
  calling_station_id  CHAR_T(32) COMMA
  INDEX(name_sid, user_name,acct_session_id) COMMA
  INDEX(name_stat_sid,user_name,status,acct_session_id) COMMA
  INDEX(stat_nas,status,nas_ip_address)
})

DB_PRIV
