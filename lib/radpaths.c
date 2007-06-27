/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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
#include <radlib.h>

char    *grad_config_dir;
char    *grad_log_dir;
char    *grad_acct_dir;
char    *grad_utmp_file;
char    *grad_wtmp_file;
char    *grad_stat_file;
char    *grad_msgid_file;
char    *grad_pid_dir;
char    *grad_bug_report_address = "bug-gnu-radius@gnu.org";

void
grad_path_init()
{
        if (!grad_config_dir)
                grad_config_dir = grad_estrdup(RADIUS_DIR);
        if (!grad_log_dir)
                grad_log_dir = grad_estrdup(RADLOG_DIR);
        if (!grad_acct_dir)
                grad_acct_dir = grad_estrdup(RADACCT_DIR);
        if (!grad_pid_dir)
                grad_pid_dir = grad_estrdup(RADPID_DIR);

        grad_free(grad_utmp_file);
        grad_utmp_file = grad_mkfilename(grad_log_dir, RADUTMP);

        grad_free(grad_wtmp_file);
        grad_wtmp_file = grad_mkfilename(grad_log_dir, RADWTMP);

        grad_free(grad_stat_file);
        grad_stat_file = grad_mkfilename(grad_log_dir, RADSTAT);

	grad_free(grad_msgid_file);
	grad_msgid_file = grad_mkfilename(grad_log_dir, RADMSGID);
}

void
grad_path_free()
{
	grad_destroy((void**)&grad_config_dir);
	grad_destroy((void**)&grad_log_dir);
	grad_destroy((void**)&grad_acct_dir);
	grad_destroy((void**)&grad_utmp_file);
	grad_destroy((void**)&grad_wtmp_file);
	grad_destroy((void**)&grad_stat_file);
	grad_destroy((void**)&grad_msgid_file);
	grad_destroy((void**)&grad_pid_dir);
}
