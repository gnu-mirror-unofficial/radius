/* This file is part of GNU Radius.
   Copyright (C) 2001,2002,2003 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff
 
   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.
 
   GNU Radius is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. */

int
strcspn(char *s1, char *s2)
{
        register char *scan1;
        register char *scan2;
        register int count;

        count = 0;
        for (scan1 = s1; *scan1; scan1++) {
                for (scan2 = s2; *scan2;)       
                        if (*scan1 == *scan2++)
                                return count;
                count++;
        }
        return count;
}
