#! /bin/sh

autoreconf -f -i -s

if [ ! -r include/debugmod.h ]; then
    echo "NOTE: Now you should do the following:"
    echo "    ./configure --enable-maintainer-mode [other options]"
    echo "    make debugmod"
    echo "    make"
fi
