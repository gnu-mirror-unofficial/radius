/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <radiusd.h>
#include <radpaths.h>

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

char	*radius_dir;
char	*radlog_dir;
char	*radacct_dir;
char    *radutmp_path;
char    *radwtmp_path;
char    *radstat_path;

void
radpath_init()
{
	if (!radius_dir)
		radius_dir = RADIUS_DIR;
	if (!radlog_dir)
		radlog_dir = RADLOG_DIR;
	if (!radacct_dir)
		radacct_dir = RADACCT_DIR;

	radutmp_path = mkfilename(radlog_dir, RADUTMP);
	radwtmp_path = mkfilename(radlog_dir, RADWTMP);
	radstat_path = mkfilename(radlog_dir, RADSTAT);
}
