/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <radius.h>
#include <radpaths.h>

char    *radius_dir;
char    *radlog_dir;
char    *radacct_dir;
char    *radutmp_path;
char    *radwtmp_path;
char    *radstat_path;
char    *radmsgid_path;
char    *radpid_dir;
char    *bug_report_address = "bug-gnu-radius@gnu.org";

void
radpath_init()
{
        if (!radius_dir)
                radius_dir = estrdup(RADIUS_DIR);
        if (!radlog_dir)
                radlog_dir = estrdup(RADLOG_DIR);
        if (!radacct_dir)
                radacct_dir = estrdup(RADACCT_DIR);
        if (!radpid_dir)
                radpid_dir = estrdup(RADPID_DIR);

        efree(radutmp_path);
        radutmp_path = mkfilename(radlog_dir, RADUTMP);

        efree(radwtmp_path);
        radwtmp_path = mkfilename(radlog_dir, RADWTMP);

        efree(radstat_path);
        radstat_path = mkfilename(radlog_dir, RADSTAT);

	efree(radmsgid_path);
	radmsgid_path = mkfilename(radlog_dir, RADMSGID);
}
