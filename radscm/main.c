/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
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

#include <libguile.h>
#include <radius.h>
#include <radscm.h>

/*ARGSUSED*/
static void
radscm_shell(void *closure ARG_UNUSED, int argc, char **argv)
{
        rad_scheme_init(argc, argv);
}

int
main(int argc, char **argv)
{
        /*app_setup();*/
        initlog(argv[0]);
        
        scm_boot_guile(argc, argv, radscm_shell, 0);
        /*NOTREACHED*/
}


