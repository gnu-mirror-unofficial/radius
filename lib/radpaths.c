/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public
   License along with GNU Radius; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA. */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <common.h>

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
grad_path_init()
{
        if (!radius_dir)
                radius_dir = grad_estrdup(RADIUS_DIR);
        if (!radlog_dir)
                radlog_dir = grad_estrdup(RADLOG_DIR);
        if (!radacct_dir)
                radacct_dir = grad_estrdup(RADACCT_DIR);
        if (!radpid_dir)
                radpid_dir = grad_estrdup(RADPID_DIR);

        grad_free(radutmp_path);
        radutmp_path = grad_mkfilename(radlog_dir, RADUTMP);

        grad_free(radwtmp_path);
        radwtmp_path = grad_mkfilename(radlog_dir, RADWTMP);

        grad_free(radstat_path);
        radstat_path = grad_mkfilename(radlog_dir, RADSTAT);

	grad_free(radmsgid_path);
	radmsgid_path = grad_mkfilename(radlog_dir, RADMSGID);
}

void
grad_path_free()
{
	grad_destroy((void**)&radius_dir);
	grad_destroy((void**)&radlog_dir);
	grad_destroy((void**)&radacct_dir);
	grad_destroy((void**)&radutmp_path);
	grad_destroy((void**)&radwtmp_path);
	grad_destroy((void**)&radstat_path);
	grad_destroy((void**)&radmsgid_path);
	grad_destroy((void**)&radpid_dir);
}
