/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2004,2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
  
   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.
  
   GNU Radius is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <gettext.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#include <common.h>

void
grad_app_setup()
{
#ifdef ENABLE_NLS
#ifdef HAVE_SETLOCALE
        setlocale(LC_ALL, "");
#endif
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif
	grad_set_logger(grad_default_logger);
}
