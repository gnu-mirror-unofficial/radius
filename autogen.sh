#! /bin/sh

autoreconf -f -i -s &&\
 mv intl/Makefile.in intl/Makefile.in~ &&\
 sed 's,^INCLUDES.*,& -I$(top_srcdir)/include,' intl/Makefile.in~ > intl/Makefile.in && \
 if [ ! -r include/debugmod.h ]; then
    echo "NOTE: Now you should do the following:"
    echo "    ./configure --enable-maintainer-mode [other options]"
    echo "    make debugmod"
    echo "    make"
 fi
