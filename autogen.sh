#! /bin/sh

autoreconf -f -i -s &&\
 mv intl/Makefile.in intl/Makefile.in~ &&\
 sed 's,^INCLUDES.*,& -I$(top_srcdir)/include,' intl/Makefile.in~ > intl/Makefile.in 
