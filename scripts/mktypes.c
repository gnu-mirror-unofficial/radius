char header_text[] = "\
/* This file is part of GNU Radius.\n\
   Copyright (C) 2004 Free Software Foundation, Inc.\n\
\n\
   GNU Radius is free software; you can redistribute it and/or modify\n\
   it under the terms of the GNU General Public License as published by\n\
   the Free Software Foundation; either version 2 of the License, or\n\
   (at your option) any later version.\n\
\n\
   GNU Radius is distributed in the hope that it will be useful,\n\
   but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
   GNU General Public License for more details.\n\
\n\
   You should have received a copy of the GNU General Public License\n\
   along with GNU Radius; if not, write to the Free Software Foundation,\n\
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.\n\
\n\
   This file is generated automatically. Please do not edit.*/";

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <sys/types.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifndef DEF_AUTH_PORT
# define DEF_AUTH_PORT  1812
#endif
#ifndef DEF_ACCT_PORT
# define DEF_ACCT_PORT  1813
#endif

int
main()
{
	printf("%s\n\n", header_text);
	printf("#include <sys/types.h>\n");
#ifdef HAVE_STDINT_H
	printf("#include <stdint.h>\n");
#endif
	printf("\n");
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


	printf("/* End of radius/types.h */\n");
	return 0;
}
