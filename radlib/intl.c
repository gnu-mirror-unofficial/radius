#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#ifdef HAVE_SETLOCALE
#include <locale.h>
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
