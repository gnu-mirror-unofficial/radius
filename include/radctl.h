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

enum cntl_command {
	CNTL_GETPID,
	CNTL_GETMSTAT,
	CNTL_GETQSTAT,
	CNTL_GETUSER,
	CNTL_DUMPDB,
	CNTL_RELOAD,
	CNTL_RESTART,
	CNTL_SHUTDOWN,
	CNTL_SUSPEND,
	CNTL_CONTINUE,
};

#ifdef CNTL_STATE_DECL
struct keyword cntl_state[] = {
	"getpid", CNTL_GETPID,
	"get-m-stat", CNTL_GETMSTAT,
	"get-q-stat", CNTL_GETQSTAT,
	"get-user", CNTL_GETUSER,
	"dumpdb", CNTL_DUMPDB,
	"reload", CNTL_RELOAD,
	"restart", CNTL_RESTART,
	"shutdown", CNTL_SHUTDOWN,
	"suspend", CNTL_SUSPEND,
	"continue", CNTL_CONTINUE,
	NULL
};
#endif



