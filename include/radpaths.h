/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADDB_DIR SYSCONFDIR "/raddb"

#define RADIUSD_PID_FILE "radiusd.pid"

#define RADIUS_DIR              RADDB_DIR

#define RADACCT_DIR             RADLOG_DIR "/radacct"

#define RADIUS_DICTIONARY       "dictionary"
#define RADIUS_CLIENTS          "clients"
#define RADIUS_NASLIST          "naslist"
#define RADIUS_NASTYPES         "nastypes"
#define RADIUS_USERS            "users"
#define RADIUS_LOG              "radius.log"
#define RADIUS_HINTS            "hints"
#define RADIUS_HUNTGROUPS       "huntgroups"
#define RADIUS_REALMS           "realms"
#define RADIUS_CONFIG           "config"
#define RADIUS_DENY             "access.deny"

#define RADUTMP                 "radutmp"
#define RADWTMP                 "radwtmp"
#define RADMSGID                "radmsgid"

#define RADSTAT                 "radius.stat"

#define RADIUS_DUMPDB_NAME      "radius.parse"

#define RADCLIENT_CONFIG        "client.config"
#define RADCLIENT_SHADOW        "client.shadow"
