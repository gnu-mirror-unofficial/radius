/* This file is part of GNU RADIUS.
 * Copyright (C) 2000,2001, Sergey Poznyakoff
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif

void
app_setup()
{
#ifdef HAVE_SETLOCALE
	setlocale(LC_ALL, "");
#endif
#ifdef HAVE_LIBINTL
        textdomain(PACKAGE);
#endif
}
