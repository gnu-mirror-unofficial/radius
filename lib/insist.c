/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2004,2008 Free Software Foundation, Inc.

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

#include <stdlib.h>
#include <radius/radius.h>

int
__grad_insist_failure(const char *str, const char *file, int line)
{
        grad_log(GRAD_LOG_CRIT,
                 "INSIST FAILURE: %s at %s:%d", str, file, line);
        abort();
        /*NOTREACHED*/
}
