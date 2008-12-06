char header_text[] = "\
/* This file is part of GNU Radius.\n\
   Copyright (C) 2004, 2007, 2008 Free Software Foundation, Inc.\n\
\n\
   GNU Radius is free software; you can redistribute it and/or modify\n\
   it under the terms of the GNU General Public License as published by\n\
   the Free Software Foundation; either version 3 of the License, or\n\
   (at your option) any later version.\n\
\n\
   GNU Radius is distributed in the hope that it will be useful,\n\
   but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
   GNU General Public License for more details.\n\
\n\
   You should have received a copy of the GNU General Public License\n\
   along with GNU Radius; if not, write to the Free Software Foundation,\n\
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.\n\
\n\
   This file is generated automatically. Please do not edit.*/";

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifndef DEF_AUTH_PORT
# define DEF_AUTH_PORT  1812
#endif
#ifndef DEF_ACCT_PORT
# define DEF_ACCT_PORT  1813
#endif

char *
print_number(char *prefix, char *p, unsigned *acc)
{
	unsigned n = 0;
	if (isdigit(*p)) {
		printf("#define %s ", prefix);
		for (; isdigit(*p); p++) {
			putchar(*p);
			n = n * 10 + *p - '0';
		}
		putchar('\n');
	}
	*acc = n;
	return p;
}

int
main()
{
	char *p;
	unsigned version = 0, n;
	
	printf("%s\n\n", header_text);
	printf("#ifndef _gnu_radius_types_h\n");
	printf("#define _gnu_radius_types_h\n");
	printf("#include <sys/types.h>\n");
#ifdef HAVE_STDINT_H
	printf("#include <stdint.h>\n");
#endif
	printf("\n");
	printf("#define GRAD_VERSION_STRING \"%s\"\n", PACKAGE_VERSION);
	p = PACKAGE_VERSION;
	p = print_number("GRAD_VERSION_MAJOR", p, &version);
	version *= 1000;
	if (*p == '.') {
		p++;
		p = print_number("GRAD_VERSION_MINOR", p, &n);
		version += n * 100;
		if (*p == '.') {
			p++;
			p = print_number("GRAD_VERSION_PATCH", p, &n);
			version += n;
		} else 
			printf("#define GRAD_VERSION_PATCH 0\n");
	} 
	if (*p)
		printf("#define GRAD_VERSION_EXTRA \"%s\"\n");
	printf("#define GRAD_VERSION_NUMBER %u\n", version);
	printf("typedef %s grad_uint32_t;\n",
#if SIZEOF_UINT32_T == 4
	       "uint32_t"
#elif SIZEOF_UNSIGNED_INT == 4
	       "unsigned int"
#elif SIZEOF_UNSIGNED_LONG == 4
	       "unsigned long"
#else
# error "Cannot find any 32-bit integer data type"
#endif
		);
	
	printf("#define RADIUS_AUTH_PORT %u\n", DEF_AUTH_PORT);
	printf("#define RADIUS_ACCT_PORT %u\n", DEF_ACCT_PORT);

	printf("#endif\n");
	printf("/* End of radius/types.h */\n");
	return 0;
}
